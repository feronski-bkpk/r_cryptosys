use log::{debug, info, trace, warn};
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;
use crate::error::CryptoError;

const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const HASH_LENGTH: usize = 32;
const BLOCK_SIZE: usize = 16;
const IV_LENGTH: usize = 16;

pub fn derive_key(password: &str, salt: &[u8]) -> Vec<u8> {
    debug!("[KEY] Начало генерации ключа (длина пароля: {})", password.len());
    trace!("[KEY] Используемая соль: {:02X}... (первые 2 байта)", salt[0]);

    let start_time = std::time::Instant::now();
    let password_bytes = password.as_bytes();
    let mut key = Vec::with_capacity(KEY_LENGTH);
    let mut block: i32 = 1;

    while key.len() < KEY_LENGTH {
        trace!("[KEY] Генерация блока {}", block);

        let mut u = hmac_sha256(
            password_bytes,
            &[salt, &block.to_be_bytes()].concat()
        );
        let mut t = u.clone();

        for iter in 1..PBKDF2_ITERATIONS {
            u = hmac_sha256(password_bytes, &u);
            for (i, byte) in u.iter().enumerate() {
                t[i] ^= byte;
            }

            if iter % 25_000 == 0 {
                trace!("[KEY-PBKDF2] Итерация {}/{} ({:.1}%)",
                      iter, PBKDF2_ITERATIONS,
                      (iter as f32 / PBKDF2_ITERATIONS as f32) * 100.0);
            }
        }

        key.extend_from_slice(&t);
        trace!("[KEY] Добавлен блок {} (текущая длина: {})", block, key.len());
        block += 1;
    }

    key.truncate(KEY_LENGTH);
    debug!("[KEY] Ключ сгенерирован за {:?} (финальная длина: {})",
          start_time.elapsed(), key.len());
    trace!("[KEY] Пример ключа: {:02X}{:02X}... (первые 2 байта)", key[0], key[1]);
    key
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut key_padded = vec![0; 64];
    if key.len() > 64 {
        let hash = Sha256::digest(key);
        key_padded[..hash.len()].copy_from_slice(&hash);
    } else {
        key_padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = vec![0x36; 64];
    let mut opad = vec![0x5C; 64];

    for i in 0..64 {
        ipad[i] ^= key_padded[i];
        opad[i] ^= key_padded[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_result = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_result);

    let result = outer.finalize().to_vec();
    result
}

fn block_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut encrypted = Vec::with_capacity(data.len() + BLOCK_SIZE);
    let mut prev_block = iv.to_vec();

    for chunk in data.chunks(BLOCK_SIZE) {
        let mut block = chunk.to_vec();

        if block.len() < BLOCK_SIZE {
            let pad_len = BLOCK_SIZE - block.len();
            block.extend(std::iter::repeat(pad_len as u8).take(pad_len));
        }

        for (i, byte) in block.iter_mut().enumerate() {
            *byte ^= prev_block[i % prev_block.len()] ^ key[i % key.len()];
        }

        prev_block = block.clone();
        encrypted.extend(block);
    }

    encrypted
}

fn remove_padding(data: &mut Vec<u8>) -> Result<(), CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::AuthFailed);
    }

    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > BLOCK_SIZE {
        return Err(CryptoError::AuthFailed);
    }

    if data.len() < pad_len {
        return Err(CryptoError::AuthFailed);
    }

    if !data[data.len()-pad_len..].iter().all(|&b| b == pad_len as u8) {
        return Err(CryptoError::AuthFailed);
    }

    data.truncate(data.len() - pad_len);
    Ok(())
}

fn block_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() % BLOCK_SIZE != 0 {
        return Err(CryptoError::InvalidData);
    }

    let mut decrypted = Vec::with_capacity(data.len());
    let mut prev_block = iv.to_vec();

    for chunk in data.chunks(BLOCK_SIZE) {
        let mut block = chunk.to_vec();

        for (i, byte) in block.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];
            *byte ^= prev_block[i % prev_block.len()];
        }

        prev_block = chunk.to_vec();
        decrypted.extend(block);
    }

    remove_padding(&mut decrypted)?;
    Ok(decrypted)
}

pub fn encrypt(data: &[u8], password: &str, original_extension: Option<&str>) -> Result<Vec<u8>, CryptoError> {
    info!("[ENC] Начало шифрования (данные: {}b, расширение: {:?})",
         data.len(), original_extension);

    let timer = std::time::Instant::now();
    let salt = generate_salt();
    let iv = generate_salt()[..IV_LENGTH].to_vec();
    trace!("[ENC] Соль и IV сгенерированы");

    let key = derive_key(password, &salt);
    trace!("[ENC] Ключ вычислен");

    let encrypted = block_encrypt(data, &key, &iv);
    debug!("[ENC] Данные зашифрованы (размер после шифрования: {}b)", encrypted.len());

    let mut hmac_data = Vec::new();
    hmac_data.extend(&salt);
    hmac_data.extend(&iv);
    hmac_data.extend(&encrypted);

    let hmac = hmac_sha256(&key, &hmac_data);
    trace!("[ENC] HMAC вычислен для соль + IV + encrypted_data");

    let ext_bytes = original_extension.unwrap_or("").as_bytes();
    let ext_len = ext_bytes.len() as u8;

    let mut result = Vec::with_capacity(
        SALT_LENGTH + IV_LENGTH + HASH_LENGTH + 1 + ext_bytes.len() + encrypted.len()
    );

    result.extend(&salt);
    result.extend(&iv);
    result.extend(&hmac);
    result.push(ext_len);
    result.extend(ext_bytes);
    result.extend(&encrypted);

    info!("[ENC] Шифрование завершено за {:?} (итоговый размер: {}b)",
         timer.elapsed(), result.len());
    trace!("[ENC] Структура данных: [соль({}byte)|IV({}byte)|хеши({}byte)|расширение({}byte)|данные({}b)]",
          SALT_LENGTH, IV_LENGTH, HASH_LENGTH*2, ext_bytes.len(), encrypted.len());
    Ok(result)
}

pub fn decrypt(data: &[u8], password: &str) -> Result<(Vec<u8>, Option<String>), CryptoError> {
    info!("[DEC] Начало дешифрования (данные: {}b)", data.len());

    let timer = std::time::Instant::now();
    let min_size = SALT_LENGTH + IV_LENGTH + HASH_LENGTH * 2 + 1;
    if data.len() < min_size {
        return Err(CryptoError::InvalidData);
    }

    trace!("[DEC] Извлечение компонентов из данных");
    let salt = &data[..SALT_LENGTH];
    let iv = &data[SALT_LENGTH..SALT_LENGTH + IV_LENGTH];
    let stored_hmac = &data[SALT_LENGTH + IV_LENGTH..SALT_LENGTH + IV_LENGTH + HASH_LENGTH];
    let ext_len = data[SALT_LENGTH + IV_LENGTH + HASH_LENGTH] as usize;
    let ext_start = SALT_LENGTH + IV_LENGTH + HASH_LENGTH + 1;
    let ext_end = ext_start + ext_len;
    let encrypted = &data[ext_end..];

    if ext_end > data.len() {
        return Err(CryptoError::InvalidData);
    }

    let original_extension = if ext_len > 0 {
        Some(String::from_utf8(data[ext_start..ext_end].to_vec())?)
    } else {
        None
    };

    trace!("[DEC] Проверка HMAC данных...");
    let mut hmac_data = Vec::new();
    hmac_data.extend(salt);
    hmac_data.extend(iv);
    hmac_data.extend(encrypted);

    let key = derive_key(password, salt);
    let computed_hmac = hmac_sha256(&key, &hmac_data);

    if computed_hmac.ct_ne(stored_hmac).unwrap_u8() == 1 {
        warn!("[DEC] Ошибка аутентификации: неверный пароль или поврежденные данные");
        return Err(CryptoError::AuthFailed);
    }
    debug!("[DEC] Данные верифицированы");

    let decrypted = block_decrypt(encrypted, &key, iv)?;

    info!("[DEC] Дешифрование завершено за {:?} (данные: {}b, расширение: {:?})",
         timer.elapsed(), decrypted.len(), original_extension);
    trace!("[DEC] Пример данных: {:02X}... (первые 2 байта)", decrypted[0]);
    Ok((decrypted, original_extension))
}

pub(crate) fn generate_salt() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};

    trace!("[SALT] Начало генерации соли");
    let start_time = std::time::Instant::now();

    let mut salt = vec![0u8; SALT_LENGTH];
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for (i, byte) in salt.iter_mut().enumerate() {
        let shift = (i * 8) % 128;
        *byte = ((time >> shift) & 0xFF) as u8;
        trace!("[SALT] Байт {}: {:02X} (сдвиг {})", i, *byte, shift);
    }

    debug!("[SALT] Соль сгенерирована за {:?}", start_time.elapsed());
    trace!("[SALT] Пример соли: {:02X}{:02X}... (первые 2 байта)", salt[0], salt[1]);
    salt
}