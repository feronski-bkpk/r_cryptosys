use std::io::{self, Write};
use crate::error::CryptoError;

#[cfg(unix)]
extern crate libc;

pub fn read_password(prompt: &str) -> Result<String, CryptoError> {
    print!("{}", prompt);
    io::stdout().flush()?;

    #[cfg(unix)]
    let _ = unsafe { libc::system("stty -echo") };

    let mut password = String::new();
    io::stdin().read_line(&mut password)?;

    #[cfg(unix)]
    let _ = unsafe { libc::system("stty echo") };

    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }

    println!();

    Ok(password)
}