use rfd::FileDialog;
use std::path::{PathBuf};
use crate::error::CryptoError;

pub fn show_file_dialog_safe(default_path: &str) -> Result<Option<PathBuf>, CryptoError> {
    match get_absolute_path(default_path) {
        Some(path) => Ok(FileDialog::new()
            .set_directory(path)
            .pick_file()),
        None => Err(CryptoError::DialogError(
            "Не удалось найти исходную директорию".to_string()
        ))
    }
}

pub fn show_dir_dialog_safe(default_path: &str) -> Result<Option<PathBuf>, CryptoError> {
    match get_absolute_path(default_path) {
        Some(path) => Ok(FileDialog::new()
            .set_directory(path)
            .pick_folder()),
        None => Err(CryptoError::DialogError(
            "Не удалось найти исходную директорию".to_string()
        ))
    }
}

pub fn show_encrypted_file_dialog_safe(default_path: &str) -> Result<Option<PathBuf>, CryptoError> {
    match get_absolute_path(default_path) {
        Some(path) => Ok(FileDialog::new()
            .set_directory(path)
            .add_filter("Encrypted", &["enc"])
            .pick_file()),
        None => Err(CryptoError::DialogError(
            "Не удалось найти директорию с зашифрованными файлами".to_string()
        ))
    }
}

fn get_absolute_path(relative_path: &str) -> Option<PathBuf> {
    std::env::current_dir()
        .ok()
        .map(|p| p.join(relative_path))
        .filter(|p| p.exists())
}


pub fn read_input(prompt: &str) -> String {
    use std::io::{self, Write};
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

pub fn print_menu() {
    println!("\nМеню:");
    println!("1. Зашифровать файл/директорию");
    println!("2. Расшифровать файл");
    println!("3. Выход");
}

pub fn print_success(message: &str) {
    println!("✓ {}", message);
}

pub fn print_error(message: &str) {
    eprintln!("✗ {}", message);
}