use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Data integrity check failed")]
    IntegrityCheckFailed,

    #[error("Invalid data format")]
    InvalidData,

    #[error("Invalid file name")]
    InvalidFileName,

    #[error("File must have .enc extension")]
    NotEncryptedFile,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Archive error: {0}")]
    ArchiveError(String),

    #[error("Path error: {0}")]
    PathError(String),

    #[error("File already exists: {0}")]
    FileExists(String),

    #[error("Dialog error: {0}")]
    DialogError(String),

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Директория не найдена: {0}")]
    DirectoryNotFound(String),

    #[error("Файл не найден: {0}")]
    FileNotFound(String),
}

impl From<walkdir::Error> for CryptoError {
    fn from(err: walkdir::Error) -> Self {
        CryptoError::Io(err.into())
    }
}

impl From<std::path::StripPrefixError> for CryptoError {
    fn from(err: std::path::StripPrefixError) -> Self {
        CryptoError::PathError(err.to_string())
    }
}