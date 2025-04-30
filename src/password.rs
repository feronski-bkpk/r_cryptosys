use std::io::{self, Write};
use crate::error::CryptoError;

pub fn read_password(prompt: &str) -> Result<String, CryptoError> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let mut password = String::new();
    io::stdin().read_line(&mut password)?;

    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }

    println!();

    Ok(password)
}