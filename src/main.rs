mod crypto;
mod error;
mod files;
mod ui;
mod logger;

use std::path::Path;
use std::fs;
use clap::Parser;
use log::{error, info, warn};
use crate::error::CryptoError;
use crate::files::{create_archive, extract_archive};
use crate::ui::*;
use crate::crypto::{encrypt, decrypt};
use crate::logger::{CryptoLogger};

const SOURCE_DIR: &str = "source_files";
const ENCRYPTED_DIR: &str = "encrypted";
const DECRYPTED_DIR: &str = "decrypted";
//const LOG_FILE: &str = "crypto_tool.log";

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Включить подробное логирование
    #[arg(long)]
    verbose: bool,
}

fn main() {
    // Получаем аргументы командной строки
    let args: Vec<String> = std::env::args().collect();

    // Проверяем 3-й аргумент (индекс 2) на наличие "--verbose"
    let verbose = args.get(1).map_or(false, |arg| arg == "verbose");

    // Инициализация логгера
    CryptoLogger::init(verbose, "logs/r_cryptosys.log")
        .expect("Не удалось инициализировать логгер");

    info!("Starting application (verbose: {})", verbose);

    if let Err(e) = run() {
        error!("Application error: {}", e);
        eprintln!("Ошибка: {}", e);
    }

    info!("Application shutdown");
}

fn run() -> Result<(), CryptoError> {
    // Создаем абсолютные пути
    let source_dir = std::env::current_dir()?.join(SOURCE_DIR);
    let encrypted_dir = std::env::current_dir()?.join(ENCRYPTED_DIR);
    let decrypted_dir = std::env::current_dir()?.join(DECRYPTED_DIR);

    // Создаем директории
    fs::create_dir_all(&source_dir)?;
    fs::create_dir_all(&encrypted_dir)?;
    fs::create_dir_all(&decrypted_dir)?;

    info!("Directories initialized: source={}, encrypted={}, decrypted={}",
        source_dir.display(), encrypted_dir.display(), decrypted_dir.display());

    loop {
        print_menu();
        let choice = read_input("Выберите опцию: ");

        match choice.as_str() {
            "1" => {
                info!("User selected encryption");
                handle_encrypt()?;
            },
            "2" => {
                info!("User selected decryption");
                handle_decrypt()?;
            },
            "3" => {
                info!("User selected exit");
                break;
            },
            _ => {
                warn!("Invalid menu option selected: {}", choice);
                println!("Неверная опция");
            }
        }
    }
    Ok(())
}

fn handle_encrypt() -> Result<(), CryptoError> {
    println!("1. Файл\n2. Директория");
    let choice = read_input("> ");
    let password = read_password("Введите пароль для шифрования: ")?;

    match choice.as_str() {
        "1" => {
            info!("File encryption selected");
            match show_file_dialog_safe(SOURCE_DIR)? {
                Some(path) => encrypt_file(&path, &password),
                None => {
                    info!("File selection cancelled by user");
                    Ok(())
                }
            }
        },
        "2" => {
            info!("Directory encryption selected");
            match show_dir_dialog_safe(SOURCE_DIR)? {
                Some(path) => encrypt_directory(&path, &password),
                None => {
                    info!("Directory selection cancelled by user");
                    Ok(())
                }
            }
        },
        _ => {
            warn!("Invalid encryption type selected: {}", choice);
            println!("Неверный выбор");
            Ok(())
        }
    }
}

fn handle_decrypt() -> Result<(), CryptoError> {
    info!("Starting decryption process");
    match show_encrypted_file_dialog_safe(ENCRYPTED_DIR)? {
        Some(path) => {
            if path.extension().and_then(|e| e.to_str()) != Some("enc") {
                warn!("Invalid file extension: {}", path.display());
                print_error("Файл должен иметь расширение .enc");
                return Ok(());
            }

            let password = read_password("Введите пароль для дешифрования: ")?;
            decrypt_file(&path, &password)
        },
        None => {
            info!("Decryption file selection cancelled by user");
            Ok(())
        }
    }
}

fn encrypt_file(path: &Path, password: &str) -> Result<(), CryptoError> {
    info!("Encrypting file: {}", path.display());
    let data = fs::read(path)?;

    let encrypted = match encrypt(&data, password) {
        Ok(e) => e,
        Err(e) => {
            error!("Encryption failed for file: {}", path.display());
            return Err(e);
        }
    };

    let file_name = path.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            error!("Invalid file name: {}", path.display());
            CryptoError::InvalidFileName
        })?;

    let dest_path = Path::new(ENCRYPTED_DIR).join(format!("{}.enc", file_name));
    fs::write(&dest_path, encrypted)?;

    info!("File encrypted successfully: {} -> {}",
        path.display(), dest_path.display());
    print_success(&format!("Файл '{}' успешно зашифрован", file_name));
    Ok(())
}

fn encrypt_directory(path: &Path, password: &str) -> Result<(), CryptoError> {
    info!("Encrypting directory: {}", path.display());
    let archive = match create_archive(path) {
        Ok(a) => a,
        Err(e) => {
            error!("Archive creation failed for directory: {}", path.display());
            return Err(e);
        }
    };

    let encrypted = match encrypt(&archive, password) {
        Ok(e) => e,
        Err(e) => {
            error!("Directory encryption failed: {}", path.display());
            return Err(e);
        }
    };

    let dir_name = path.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            error!("Invalid directory name: {}", path.display());
            CryptoError::InvalidFileName
        })?;

    let dest_path = Path::new(ENCRYPTED_DIR).join(format!("{}.enc", dir_name));
    fs::write(&dest_path, encrypted)?;

    info!("Directory encrypted successfully: {} -> {}",
        path.display(), dest_path.display());
    print_success(&format!("Директория '{}' успешно зашифрована", dir_name));
    Ok(())
}

fn decrypt_file(path: &Path, password: &str) -> Result<(), CryptoError> {
    info!("Decrypting file: {}", path.display());
    let data = fs::read(path)?;

    let decrypted = match decrypt(&data, password) {
        Ok(d) => d,
        Err(_) => {
            error!("Decryption failed for file: {}", path.display());
            print_error("Ошибка дешифрования: неверный пароль или повреждённый файл");
            return Ok(());
        }
    };

    let file_stem = path.file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            error!("Invalid file name: {}", path.display());
            CryptoError::InvalidFileName
        })?;

    let dest_path = Path::new(DECRYPTED_DIR).join(file_stem);

    // Обработка существующего файла/директории
    if dest_path.exists() {
        info!("Target path exists, removing: {}", dest_path.display());
        if dest_path.is_dir() {
            fs::remove_dir_all(&dest_path).map_err(|e| {
                error!("Failed to remove directory: {}", e);
                CryptoError::FileExists(dest_path.display().to_string())
            })?;
        } else {
            fs::remove_file(&dest_path).map_err(|e| {
                error!("Failed to remove file: {}", e);
                CryptoError::FileExists(dest_path.display().to_string())
            })?;
        }
    }

    match extract_archive(&decrypted, &dest_path) {
        Ok(_) => {
            info!("File decrypted successfully: {} -> {}",
                path.display(), dest_path.display());
            print_success(&format!("Файл '{}' успешно дешифрован", file_stem));
            Ok(())
        },
        Err(e) => {
            error!("Extraction failed: {}", e);
            print_error("Ошибка распаковки файла");
            Ok(())
        }
    }
}

fn read_password(prompt: &str) -> Result<String, CryptoError> {
    use std::io::{self, Write};
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    Ok(password.trim().to_string())
}