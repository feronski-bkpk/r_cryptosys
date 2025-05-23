use log::{error, info, trace, warn};
use subtle::ConstantTimeEq;
use std::time::{Instant, Duration};
use crate::error::CryptoError;
use crate::sha256;

const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const HASH_LENGTH: usize = 32;
const BLOCK_SIZE: usize = 16;
const IV_LENGTH: usize = 16;
const ROUNDS: usize = 1;

static SUBSTITUTION_BOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
];

static INV_S_BOX: [u8; 256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
];

#[derive(Debug)]
pub struct CryptoMetrics {
    pub duration: Duration,
    pub speed_mbps: f64,
}

impl CryptoMetrics {
    pub fn new(data_size: usize, duration: Duration) -> Self {
        let speed_mbps = (data_size as f64 * 8.0) / (duration.as_secs_f64() * 1_000_000.0);
        CryptoMetrics {
            duration,
            speed_mbps,
        }
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut key_padded = vec![0; 64];
    if key.len() > 64 {
        trace!("[HMAC] Ключ слишком длинный, хешируем его");
        let hash = sha256(key);
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

    let mut inner_input = Vec::new();
    inner_input.extend(&ipad);
    inner_input.extend(data);
    let inner_result = sha256(&inner_input);

    let mut outer_input = Vec::new();
    outer_input.extend(&opad);
    outer_input.extend(&inner_result);
    let result = sha256(&outer_input).to_vec();

    result
}

pub fn derive_key(password: &str, salt: &[u8]) -> Vec<u8> {
    info!("[KEY] Начало генерации ключа ({} итераций)", PBKDF2_ITERATIONS);
    trace!("[KEY] Пароль: {}b, Соль: {:?}", password.len(), salt);

    let start_time = Instant::now();
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

        for iteration in 1..PBKDF2_ITERATIONS {
            if iteration % 10_000 == 0 {
                trace!("[KEY] Итерация {}/{}", iteration, PBKDF2_ITERATIONS);
            }
            u = hmac_sha256(password_bytes, &u);
            for (i, byte) in u.iter().enumerate() {
                t[i] ^= byte;
            }
        }

        key.extend_from_slice(&t);
        block += 1;
    }

    key.truncate(KEY_LENGTH);
    info!(
        "[KEY] Ключ сгенерирован за {:?} (скорость: {:.2} Мбит/сек)",
        start_time.elapsed(),
        (KEY_LENGTH as f64 * 8.0 * PBKDF2_ITERATIONS as f64) / start_time.elapsed().as_secs_f64() / 1_000_000.0
    );
    key
}

pub fn encrypt(data: &[u8], password: &str, original_extension: Option<&str>) -> Result<(Vec<u8>, CryptoMetrics), CryptoError> {
    let timer = Instant::now();
    info!("[ENC] Начало шифрования (данные: {}b)", data.len());
    trace!("[ENC] Расширение файла: {:?}", original_extension);

    let salt = generate_salt();
    trace!("[ENC] Соль: {:?}", salt);

    let iv = generate_salt()[..IV_LENGTH].to_vec();
    trace!("[ENC] Вектор инициализации: {:?}", iv);

    let key = derive_key(password, &salt);

    let encrypted = block_encrypt(data, &key, &iv);
    info!("[ENC] Данные зашифрованы ({} блоков)", encrypted.len() / BLOCK_SIZE);

    let mut hmac_data = Vec::new();
    hmac_data.extend(&salt);
    hmac_data.extend(&iv);
    hmac_data.extend(&encrypted);
    let hmac = hmac_sha256(&key, &hmac_data);
    trace!("[ENC] HMAC вычислен");

    let ext_bytes = original_extension.unwrap_or("").as_bytes();
    let ext_len = ext_bytes.len() as u8;
    trace!("[ENC] Длина расширения: {}", ext_len);

    let mut result = Vec::with_capacity(SALT_LENGTH + IV_LENGTH + HASH_LENGTH + 1 + ext_bytes.len() + encrypted.len());
    result.extend(&salt);
    result.extend(&iv);
    result.extend(&hmac);
    result.push(ext_len);
    result.extend(ext_bytes);
    result.extend(&encrypted);

    let metrics = CryptoMetrics::new(data.len(), timer.elapsed());
    info!(
        "[ENC] Шифрование завершено за {:?} (скорость: {:.2} Мбит/сек)",
        metrics.duration, metrics.speed_mbps
    );

    Ok((result, metrics))
}

pub fn decrypt(data: &[u8], password: &str) -> Result<(Vec<u8>, Option<String>, CryptoMetrics), CryptoError> {
    let timer = Instant::now();
    info!("[DEC] Начало дешифрования (данные: {}b)", data.len());

    let min_size = SALT_LENGTH + IV_LENGTH + HASH_LENGTH + 1;
    if data.len() < min_size {
        error!("[DEC] Недостаточный размер данных ({} < {})", data.len(), min_size);
        return Err(CryptoError::InvalidData);
    }

    let salt = &data[..SALT_LENGTH];
    trace!("[DEC] Соль: {:?}", salt);

    let iv = &data[SALT_LENGTH..SALT_LENGTH + IV_LENGTH];
    trace!("[DEC] Вектор инициализации: {:?}", iv);

    let stored_hmac = &data[SALT_LENGTH + IV_LENGTH..SALT_LENGTH + IV_LENGTH + HASH_LENGTH];
    let ext_len = data[SALT_LENGTH + IV_LENGTH + HASH_LENGTH] as usize;
    let ext_start = SALT_LENGTH + IV_LENGTH + HASH_LENGTH + 1;
    let ext_end = ext_start + ext_len;
    let encrypted = &data[ext_end..];

    if ext_end > data.len() {
        error!("[DEC] Некорректная длина расширения ({} > {})", ext_end, data.len());
        return Err(CryptoError::InvalidData);
    }

    trace!("[DEC] Длина расширения: {}", ext_len);

    let mut hmac_data = Vec::new();
    hmac_data.extend(salt);
    hmac_data.extend(iv);
    hmac_data.extend(encrypted);

    let key = derive_key(password, salt);
    let computed_hmac = hmac_sha256(&key, &hmac_data);

    if computed_hmac.ct_ne(stored_hmac).unwrap_u8() == 1 {
        warn!("[DEC] Ошибка аутентификации HMAC");
        return Err(CryptoError::AuthFailed);
    }
    trace!("[DEC] HMAC проверен успешно");

    let decrypted = block_decrypt(encrypted, &key, iv)?;
    info!("[DEC] Данные расшифрованы ({} блоков)", decrypted.len() / BLOCK_SIZE);

    let original_extension = if ext_len > 0 {
        let ext = String::from_utf8(data[ext_start..ext_end].to_vec())?;
        trace!("[DEC] Расширение файла: {}", ext);
        Some(ext)
    } else {
        None
    };

    let metrics = CryptoMetrics::new(decrypted.len(), timer.elapsed());
    info!(
        "[DEC] Дешифрование завершено за {:?} (скорость: {:.2} Мбит/сек)",
        metrics.duration, metrics.speed_mbps
    );

    Ok((decrypted, original_extension, metrics))
}

const ROTATE_LEFT_SHIFT: usize = BLOCK_SIZE / 2;
const ROTATE_RIGHT_SHIFT: usize = BLOCK_SIZE / 2;
const ROTATE_LEFT_SHIFT2: usize = BLOCK_SIZE / 3;
const ROTATE_RIGHT_SHIFT2: usize = BLOCK_SIZE / 3;

const IDX_ADD: [usize; BLOCK_SIZE] = {
    let mut arr = [0; BLOCK_SIZE];
    let mut i = 0;
    while i < BLOCK_SIZE {
        arr[i] = (i * 11 + 3) % BLOCK_SIZE;
        i += 1;
    }
    arr
};

const IDX_XOR: [usize; BLOCK_SIZE] = {
    let mut arr = [0; BLOCK_SIZE];
    let mut i = 0;
    while i < BLOCK_SIZE {
        arr[i] = (i * 7 + 1) % BLOCK_SIZE;
        i += 1;
    }
    arr
};

#[inline(always)]
fn apply_sbox(block: &mut [u8; BLOCK_SIZE], sbox: &[u8; 256]) {
    for byte in block.iter_mut() {
        *byte = sbox[*byte as usize];
    }
}

#[inline(always)]
fn xor_blocks(block: &mut [u8; BLOCK_SIZE], other: &[u8; BLOCK_SIZE]) {
    for (a, b) in block.iter_mut().zip(other.iter()) {
        *a ^= *b;
    }
}

#[inline(always)]
fn xor_round_key(block: &mut [u8; BLOCK_SIZE], key: &[u8]) {
    let key_len = key.len();
    for (i, byte) in block.iter_mut().enumerate() {
        *byte ^= key[i % key_len];
    }
}

fn block_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let block_count = data.len().div_ceil(BLOCK_SIZE);
    trace!("[BLOCK-ENC] Начало шифрования блоков (данные: {}b)", data.len());
    trace!("[BLOCK-ENC] Всего блоков: {}", block_count);
    let timer = Instant::now();

    let mut encrypted = Vec::with_capacity(data.len() + BLOCK_SIZE);
    let round_keys = expand_key(key, ROUNDS);
    trace!("[BLOCK-ENC] Ключи раундов сгенерированы");
    let sbox = &SUBSTITUTION_BOX;

    let mut prev_block = [0u8; BLOCK_SIZE];
    prev_block[..iv.len().min(BLOCK_SIZE)].copy_from_slice(&iv[..iv.len().min(BLOCK_SIZE)]);

    for chunk in data.chunks_exact(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);

        xor_blocks(&mut block, &prev_block);

        for round_key in &round_keys {
            apply_sbox(&mut block, sbox);
            block.rotate_left(ROTATE_LEFT_SHIFT);

            for i in 0..BLOCK_SIZE {
                let j = IDX_ADD[i];
                block[i] = block[i].wrapping_add(block[j]).rotate_left(3);
            }

            xor_round_key(&mut block, round_key);
            apply_sbox(&mut block, sbox);
            block.rotate_left(ROTATE_LEFT_SHIFT2);

            for i in 0..BLOCK_SIZE {
                let j = IDX_XOR[i];
                block[i] ^= block[j].rotate_left(5);
            }
        }

        prev_block = block;
        encrypted.extend_from_slice(&block);
    }

    let rem = data.chunks_exact(BLOCK_SIZE).remainder();
    if !rem.is_empty() {
        let mut block = [0u8; BLOCK_SIZE];
        let pad_len = BLOCK_SIZE - rem.len();
        block[..rem.len()].copy_from_slice(rem);
        block[rem.len()..].fill(pad_len as u8);

        xor_blocks(&mut block, &prev_block);

        for round_key in &round_keys {
            apply_sbox(&mut block, sbox);
            block.rotate_left(ROTATE_LEFT_SHIFT);

            for i in 0..BLOCK_SIZE {
                let j = IDX_ADD[i];
                block[i] = block[i].wrapping_add(block[j]).rotate_left(3);
            }

            xor_round_key(&mut block, round_key);
            apply_sbox(&mut block, sbox);
            block.rotate_left(ROTATE_LEFT_SHIFT2);

            for i in 0..BLOCK_SIZE {
                let j = IDX_XOR[i];
                block[i] ^= block[j].rotate_left(5);
            }
        }

        encrypted.extend_from_slice(&block);
    }

    let end_time = timer.elapsed();
    info!(
        "[BLOCK-ENC] Завершено: {} блоков за {:?} ({:.2} Мбит/сек)",
        block_count,
        end_time,
        (data.len() as f64 * 8.0 / end_time.as_secs_f64()) / 1_000_000.0
    );
    encrypted
}

fn block_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let block_count = data.len() / BLOCK_SIZE;
    trace!("[BLOCK-DEC] Начало дешифрования блоков (данные: {}b)", data.len());
    trace!("[BLOCK-DEC] Всего блоков: {}", block_count);
    let timer = Instant::now();

    let d_len = data.len();
    if d_len % BLOCK_SIZE != 0 {
        error!("[BLOCK-DEC] Некорректный размер данных ({} не кратно {})", d_len, BLOCK_SIZE);
        return Err(CryptoError::InvalidData);
    }

    let mut decrypted = Vec::with_capacity(data.len());
    let round_keys = expand_key(key, ROUNDS);
    trace!("[BLOCK-DEC] Ключи раундов сгенерированы");
    let inv_sbox = &INV_S_BOX;

    let mut prev_block = [0u8; BLOCK_SIZE];
    prev_block[..iv.len().min(BLOCK_SIZE)].copy_from_slice(&iv[..iv.len().min(BLOCK_SIZE)]);

    for chunk in data.chunks_exact(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);
        let original_block = block; // Сохраняем для XOR

        for round_key in round_keys.iter().rev() {
            for i in (0..BLOCK_SIZE).rev() {
                let j = IDX_XOR[i];
                block[i] ^= block[j].rotate_left(5);
            }

            block.rotate_right(ROTATE_RIGHT_SHIFT2);
            apply_sbox(&mut block, inv_sbox);
            xor_round_key(&mut block, round_key);

            for i in (0..BLOCK_SIZE).rev() {
                let j = IDX_ADD[i];
                block[i] = block[i].rotate_right(3).wrapping_sub(block[j]);
            }

            block.rotate_right(ROTATE_RIGHT_SHIFT);
            apply_sbox(&mut block, inv_sbox);
        }

        xor_blocks(&mut block, &prev_block);
        prev_block = original_block;
        decrypted.extend_from_slice(&block);
    }

    remove_padding(&mut decrypted)?;
    trace!("[BLOCK-DEC] Padding удален");

    let end_time = timer.elapsed();
    info!(
        "[BLOCK-DEC] Завершено: {} блоков за {:?} ({:.2} Мбит/сек)",
        block_count,
        end_time,
        (data.len() as f64 * 8.0 / end_time.as_secs_f64()) / 1_000_000.0
    );
    Ok(decrypted)
}

fn expand_key(key: &[u8], rounds: usize) -> Vec<Vec<u8>> {
    let mut round_keys = Vec::with_capacity(rounds);
    let mut current_key = key.to_vec();

    for round in 0..rounds {
        let new_key: Vec<_> = current_key.iter()
            .enumerate()
            .map(|(i, &byte)| {
                let r = round as u8;
                byte.wrapping_add(r ^ (i as u8))
                    .rotate_left(((i + r as usize) % 7 + 1) as u32)
                    .wrapping_mul(0x9D) ^ 0x55
            })
            .collect();

        round_keys.push(new_key.clone());
        current_key = new_key;
    }

    trace!("[KEY-EXP] Ключи раундов сгенерированы");
    round_keys
}

fn remove_padding(data: &mut Vec<u8>) -> Result<(), CryptoError> {
    let pad_len = *data.last().ok_or({error!("[PAD] Пустые данные");CryptoError::AuthFailed})? as usize;
    trace!("[PAD] Длина padding: {}", pad_len);

    if pad_len == 0 || pad_len > BLOCK_SIZE || data.len() < pad_len {
        error!("[PAD] Некорректная длина padding");
        return Err(CryptoError::AuthFailed);
    }

    if !data[data.len()-pad_len..].iter().all(|&b| b == pad_len as u8) {
        error!("[PAD] Неверные байты padding");
        return Err(CryptoError::AuthFailed);
    }

    data.truncate(data.len() - pad_len);
    Ok(())
}

pub(crate) fn generate_salt() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::process;

    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let heap_addr = Box::into_raw(Box::new(42)) as usize;
    let pid = process::id();

    let mut input = Vec::new();
    input.extend(time.to_le_bytes());
    input.extend(heap_addr.to_le_bytes());
    input.extend(pid.to_le_bytes());

    let hash = sha256(&input);
    let salt = hash[..16].to_vec();
    trace!("[SALT] Сгенерирована соль: {:?}", salt);
    salt
}