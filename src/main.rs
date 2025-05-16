mod crypto;
mod error;
mod files;
mod ui;
mod logger;
mod password;

use std::path::Path;
use std::fs;
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use crate::error::CryptoError;
use crate::files::{create_archive, extract_archive};
use crate::ui::*;
use crate::crypto::{encrypt, decrypt};
use crate::logger::{CryptoLogger};
use crate::password::read_password;

const SOURCE_DIR: &str = "source_files";
const ENCRYPTED_DIR: &str = "encrypted";
const DECRYPTED_DIR: &str = "decrypted";
const LOG_FILE: &str = "logs/crypto_system.log";

#[derive(Parser)]
#[command(
    version,
    about = "R-Cryptosystem - simple file encryption tool",
    long_about = r#"
File and directory encryption tool.

Examples:
  Basic encryption:      r_cryptosys encrypt file.txt
  With password:         r_cryptosys encrypt doc.pdf -p 'P@ssw0rd'
  With new name:         r_cryptosys encrypt data.db -n 'backup'
  Verbose mode:          r_cryptosys --verbose encrypt archive.zip
  Directory encryption:  r_cryptosys encrypt ./documents/
"#
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(
        short,
        long,
        help = "Enable verbose logging",
        long_help = "Enables detailed logging output for debugging purposes.\nLogs are saved to logs/crypto_system.log"
    )]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        about = "Encrypt files or directories",
        long_about = r#"
Encrypt files or entire directories.

Examples:
  Encrypt file:          encrypt document.pdf
  With password:         encrypt data.xlsx -p 'S3cr3t!'
  With custom name:      encrypt photo.jpg -n 'vacation'
  Encrypt directory:     encrypt ./project_files/
"#
    )]
    Encrypt {
        path: String,

        #[arg(
            short,
            long,
            help = "Encryption password",
            long_help = "Specify password for encryption.\nIf not provided, will be prompted interactively."
        )]
        password: Option<String>,

        #[arg(
            short,
            long,
            help = "New name for encrypted file (without extension)",
            long_help = "Specify new base name for encrypted file.\nOriginal extension will be preserved automatically."
        )]
        name: Option<String>,
    },

    #[command(
        about = "Decrypt previously encrypted files",
        long_about = r#"
Decrypt files encrypted with this tool.

Examples:
  Basic decryption:      decrypt file.enc
  With password:         decrypt data.enc -p 'P@ssw0rd'
  Verbose mode:          r_cryptosys --verbose decrypt backup.enc
"#
    )]
    Decrypt {
        path: String,

        #[arg(
            short,
            long,
            help = "Decryption password",
            long_help = "Specify password for decryption.\nIf not provided, will be prompted interactively."
        )]
        password: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = CryptoLogger::init(cli.verbose, LOG_FILE) {
        eprintln!("Не удалось инициализировать логгер: {}", e);
        std::process::exit(1);
    }

    info!("Запуск приложения (verbose: {})", cli.verbose);

    match cli.command {
        Some(Commands::Encrypt { path, password, name }) => {
            info!("CLI: Режим шифрования, путь: {}", path);
            let source_path = Path::new(&path);

            #[cfg(windows)]
            if source_path.is_dir() {
                error!("Попытка шифрования директории одной командой в Windows: {}", path);
                eprintln!("На Windows шифрование директорий одной командой не поддерживается. Используйте интерактивную версию");
                std::process::exit(1);
            }

            if !source_path.exists() {
                error!("Файл/директория не найдена: {}", path);
                eprintln!("Ошибка: файл или директория '{}' не найдена", path);
                std::process::exit(1);
            }

            if let Err(e) = init_dirs() {
                error!("Ошибка инициализации директорий: {}", e);
                eprintln!("Ошибка: {}", e);
                std::process::exit(1);
            }

            let password = password.unwrap_or_else(|| {
                read_password("Введите пароль для шифрования: ")
                    .unwrap_or_else(|e| {
                        error!("Ошибка ввода пароля: {}", e);
                        eprintln!("Ошибка ввода пароля: {}", e);
                        std::process::exit(1);
                    })
            });

            info!("Начало шифрования: {}", path);
            if let Err(e) = encrypt_file(source_path, &password, name.as_deref()) {
                error!("Ошибка шифрования: {}", e);
                eprintln!("Ошибка шифрования: {}", e);
                std::process::exit(1);
            }
        },
        Some(Commands::Decrypt { path, password }) => {
            info!("CLI: Режим дешифрования, путь: {}", path);
            let encrypted_path = Path::new(&path);

            if !encrypted_path.exists() {
                error!("Файл не найден: {}", path);
                eprintln!("Ошибка: файл '{}' не найден", path);
                std::process::exit(1);
            }

            if encrypted_path.extension().and_then(|e| e.to_str()) != Some("enc") {
                error!("Неверное расширение файла: {}", path);
                eprintln!("Ошибка: файл должен иметь расширение .enc");
                std::process::exit(1);
            }

            if let Err(e) = init_dirs() {
                error!("Ошибка инициализации директорий: {}", e);
                eprintln!("Ошибка: {}", e);
                std::process::exit(1);
            }

            let password = password.unwrap_or_else(|| {
                read_password("Введите пароль для дешифрования: ")
                    .unwrap_or_else(|e| {
                        error!("Ошибка ввода пароля: {}", e);
                        eprintln!("Ошибка ввода пароля: {}", e);
                        std::process::exit(1);
                    })
            });

            info!("Начало дешифрования: {}", path);
            if let Err(e) = decrypt_file(encrypted_path, &password) {
                error!("Ошибка дешифрования: {}", e);
                eprintln!("Ошибка дешифрования: {}", e);
                std::process::exit(1);
            }
        },
        None => {
            info!("Запуск интерактивного режима");

            if let Err(e) = init_dirs() {
                error!("Ошибка инициализации директорий: {}", e);
                eprintln!("Ошибка: {}", e);
                std::process::exit(1);
            }

            if let Err(e) = run() {
                error!("Ошибка в интерактивном режиме: {}", e);
                eprintln!("Ошибка: {}", e);
                std::process::exit(1);
            }
            info!("Завершение работы интерактивного режима");
        }
    }
    info!("Приложение завершило работу");
}

fn run() -> Result<(), CryptoError> {
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

pub fn handle_encrypt() -> Result<(), CryptoError> {
    println!("1. Файл\n2. Директория");
    let choice = read_input("> ");
    let password = read_password("Введите пароль для шифрования: ")?;

    match choice.as_str() {
        "1" => {
            info!("File encryption selected");
            match show_file_dialog_safe(SOURCE_DIR)? {
                Some(path) => {
                    println!("Введите новое имя файла (без расширения, оставьте пустым для сохранения оригинального имени):");
                    let new_name = read_input("> ");
                    let new_name = if new_name.trim().is_empty() {
                        None
                    } else {
                        Some(new_name)
                    };

                    encrypt_file(&path, &password, new_name.as_deref())
                },
                None => {
                    info!("File selection cancelled by user");
                    Ok(())
                }
            }
        },
        "2" => {
            info!("Directory encryption selected");
            match show_dir_dialog_safe(SOURCE_DIR)? {
                Some(path) => {
                    println!("Введите новое имя для архива (оставьте пустым для сохранения оригинального имени):");
                    let new_name = read_input("> ");
                    let new_name = if new_name.trim().is_empty() {
                        None
                    } else {
                        Some(new_name)
                    };

                    encrypt_directory(&path, &password, new_name.as_deref())
                },
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

fn encrypt_file(path: &Path, password: &str, new_name: Option<&str>) -> Result<(), CryptoError> {
    info!("Encrypting file: {}", path.display());
    let data = fs::read(path)?;

    let original_extension = path.extension()
        .and_then(|e| e.to_str());

    let encrypted = match encrypt(&data, password, original_extension) {
        Ok(e) => e,
        Err(e) => {
            error!("Encryption failed for file: {}", path.display());
            return Err(e);
        }
    };

    let file_name = if let Some(name) = new_name {
        name.to_string()
    } else {
        path.file_stem()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                error!("Invalid file name: {}", path.display());
                CryptoError::InvalidFileName
            })?
            .to_string()
    };

    let dest_path = Path::new(ENCRYPTED_DIR).join(format!("{}.enc", file_name));
    let (encrypted_data, _) = encrypted;
    fs::write(&dest_path, encrypted_data)?;

    info!("File encrypted successfully: {} -> {}",
        path.display(), dest_path.display());
    print_success(&format!("Файл '{}' успешно зашифрован", file_name));
    Ok(())
}

fn encrypt_directory(path: &Path, password: &str, new_name: Option<&str>) -> Result<(), CryptoError> {
    info!("Encrypting directory: {}", path.display());
    let archive = match create_archive(path) {
        Ok(a) => a,
        Err(e) => {
            error!("Archive creation failed for directory: {}", path.display());
            return Err(e);
        }
    };

    // Для директорий не сохраняем расширение
    let encrypted = match encrypt(&archive, password, None) {
        Ok(e) => e,
        Err(e) => {
            error!("Directory encryption failed: {}", path.display());
            return Err(e);
        }
    };

    let dir_name = if let Some(name) = new_name {
        name.to_string()
    } else {
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                error!("Invalid directory name: {}", path.display());
                CryptoError::InvalidFileName
            })?
            .to_string()
    };

    let dest_path = Path::new(ENCRYPTED_DIR).join(format!("{}.enc", dir_name));
    let (encrypted_data, _) = encrypted;
    fs::write(&dest_path, encrypted_data)?;

    info!("Directory encrypted successfully: {} -> {}",
        path.display(), dest_path.display());
    print_success(&format!("Директория '{}' успешно зашифрована", dir_name));
    Ok(())
}

fn decrypt_file(path: &Path, password: &str) -> Result<(), CryptoError> {
    info!("Decrypting file: {}", path.display());
    let data = fs::read(path)?;

    let (decrypted, original_extension, _) = match decrypt(&data, password) {
        Ok((d, ext, m)) => (d, ext, m),
        Err(_) => {
            error!("Decryption failed for file: {}", path.display());
            print_error("Ошибка дешифрования: неверный пароль или повреждённый файл");
            return Ok(());
        }
    };

    let file_name = path.file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            error!("Invalid file name: {}", path.display());
            CryptoError::InvalidFileName
        })?;

    // Формируем имя файла с оригинальным расширением, если оно есть
    let dest_path = Path::new(DECRYPTED_DIR).join(
        if let Some(ext) = original_extension {
            format!("{}.{}", file_name, ext)
        } else {
            file_name.to_string()
        }
    );

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
            print_success(&format!("Файл '{}' успешно дешифрован", file_name));
            Ok(())
        },
        Err(e) => {
            error!("Extraction failed: {}", e);
            print_error("Ошибка распаковки файла");
            Ok(())
        }
    }
}

fn init_dirs() -> Result<(), CryptoError> {
    let dirs = [SOURCE_DIR, ENCRYPTED_DIR, DECRYPTED_DIR];
    let mut created = false;

    for dir in &dirs {
        let path = std::env::current_dir()?.join(dir);
        if !path.exists() {
            fs::create_dir_all(&path)?;
            info!("Создана директория: {}", path.display());
            created = true;
        }
    }

    if !created {
        info!("Все директории уже существуют");
    }

    Ok(())
}