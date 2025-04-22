use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, atomic::{AtomicBool, Ordering}};

static VERBOSE_MODE: AtomicBool = AtomicBool::new(false);

pub struct CryptoLogger {
    log_file: Mutex<File>,
}

impl CryptoLogger {
    pub fn init(verbose: bool, log_path: &str) -> Result<(), SetLoggerError> {
        // Устанавливаем режим verbose
        VERBOSE_MODE.store(verbose, Ordering::Relaxed);

        // Создаем директорию для логов если нужно
        if let Some(parent) = Path::new(log_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .unwrap_or_else(|_| panic!("Не удалось открыть файл логов: {}", log_path));

        let logger = CryptoLogger {
            log_file: Mutex::new(file),
        };

        log::set_boxed_logger(Box::new(logger))?;

        // Устанавливаем максимальный уровень логирования
        log::set_max_level(if verbose {
            LevelFilter::Trace
        } else {
            LevelFilter::Info
        });

        Ok(())
    }
}

impl log::Log for CryptoLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        if VERBOSE_MODE.load(Ordering::Relaxed) {
            true
        } else {
            metadata.level() <= Level::Info
        }
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let message = sanitize_message(&format!("{}", record.args()));
            let log_line = format!(
                "[{}] {}: {}\n",
                record.level(),
                record.target(),
                message
            );

            if let Ok(mut file) = self.log_file.lock() {
                let _ = file.write_all(log_line.as_bytes());
            }
        }
    }

    fn flush(&self) {
        if let Ok(mut file) = self.log_file.lock() {
            let _ = file.flush();
        }
    }
}

fn sanitize_message(msg: &str) -> String {
    msg.replace("password", "[REDACTED]")
        .replace("secret", "[REDACTED]")
        .replace("key", "[REDACTED]")
}