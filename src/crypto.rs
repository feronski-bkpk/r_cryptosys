use log::{debug, info, trace};
use sha2::{Sha256, Digest};
use crate::error::CryptoError;

const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const HASH_LENGTH: usize = 32;

pub fn derive_key(password: &str, salt: &[u8]) -> Vec<u8> {
    debug!("Начало генерации ключа (длина пароля: {}, соль: {} байт)",
           password.len(), salt.len());

    let password_bytes = password.as_bytes();
    let mut key = Vec::with_capacity(KEY_LENGTH);
    let mut block: i32 = 1;
    let mut last_logged_iteration = 0;

    while key.len() < KEY_LENGTH {
        trace!("Генерация блока {} для ключа", block);

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

            if iter - last_logged_iteration >= 1000 || iter == 1 || iter == PBKDF2_ITERATIONS - 1 {
                trace!("PBKDF2 прогресс: {}/{} ({:.1}%)",
                      iter, PBKDF2_ITERATIONS,
                      (iter as f32 / PBKDF2_ITERATIONS as f32) * 100.0);
                last_logged_iteration = iter;
            }
        }

        key.extend_from_slice(&t);
        block += 1;
    }

    key.truncate(KEY_LENGTH);
    debug!("Ключ сгенерирован (длина: {} байт)", key.len());
    key
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut ipad = vec![0x36; 64];
    let mut opad = vec![0x5C; 64];

    for (i, byte) in key.iter().enumerate().take(64) {
        ipad[i] ^= byte;
        opad[i] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_result = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_result);
    outer.finalize().to_vec()
}

pub fn encrypt(data: &[u8], password: &str) -> Result<Vec<u8>, CryptoError> {
    debug!("Starting encryption (data len: {})", data.len());

    let salt = generate_salt();
    trace!("Salt generated");

    let key = derive_key(password, &salt);
    let password_hash = hmac_sha256(password.as_bytes(), &salt);
    let data_hash = Sha256::digest(data).to_vec();

    let encrypted: Vec<u8> = data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % KEY_LENGTH])
        .collect();

    let mut result = Vec::with_capacity(SALT_LENGTH + HASH_LENGTH * 2 + encrypted.len());
    result.extend(&salt);
    result.extend(&password_hash);
    result.extend(&data_hash);
    result.extend(encrypted);

    info!("Encryption successful (total size: {})", result.len());
    Ok(result)
}

pub fn decrypt(data: &[u8], password: &str) -> Result<Vec<u8>, CryptoError> {
    debug!("Starting decryption (data len: {})", data.len());

    if data.len() < SALT_LENGTH + HASH_LENGTH * 2 {
        return Err(CryptoError::InvalidData);
    }

    let salt = &data[..SALT_LENGTH];
    let stored_pw_hash = &data[SALT_LENGTH..SALT_LENGTH+HASH_LENGTH];
    let stored_data_hash = &data[SALT_LENGTH+HASH_LENGTH..SALT_LENGTH+HASH_LENGTH*2];
    let encrypted = &data[SALT_LENGTH+HASH_LENGTH*2..];

    let computed_pw_hash = hmac_sha256(password.as_bytes(), salt);
    if computed_pw_hash != stored_pw_hash {
        return Err(CryptoError::InvalidPassword);
    }

    let key = derive_key(password, salt);
    let decrypted: Vec<u8> = encrypted.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % KEY_LENGTH])
        .collect();

    let computed_data_hash = Sha256::digest(&decrypted).to_vec();
    if computed_data_hash != stored_data_hash {
        return Err(CryptoError::IntegrityCheckFailed);
    }

    Ok(decrypted)
}

pub(crate) fn generate_salt() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};

    debug!("Генерация новой соли");
    let mut salt = vec![0u8; SALT_LENGTH];
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for (i, byte) in salt.iter_mut().enumerate() {
        *byte = ((time >> (i * 8)) & 0xFF) as u8;
    }

    trace!("Соль сгенерирована (первые 2 байта: {:02X}{:02X}...)",
        salt[0], salt[1]);
    salt
}