use log::{Log, Metadata, Record};
use std::sync::Mutex;
use std::fs::File;
use std::io::Write;
use chrono::Local;

pub struct CryptoLogger {
    log_file: Mutex<File>,
    verbose: bool,
}

impl CryptoLogger {
    pub fn init(verbose: bool, log_path: &str) -> Result<(), log::SetLoggerError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .expect("Не удалось открыть файл логов");

        let logger = CryptoLogger {
            log_file: Mutex::new(file),
            verbose,
        };

        log::set_boxed_logger(Box::new(logger))?;
        log::set_max_level(if verbose {
            log::LevelFilter::Trace
        } else {
            log::LevelFilter::Info
        });

        Ok(())
    }

    fn format_log_line(&self, record: &Record) -> String {
        format!(
            "[{}] [{}] {}: {}\n",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            record.target(),
            self.sanitize_message(&format!("{}", record.args()))
        )
    }

    fn sanitize_message(&self, msg: &str) -> String {
        msg.replace("password", "[REDACTED]")
            .replace("secret", "[REDACTED]")
            .replace("key", "[REDACTED]")
    }
}

impl Log for CryptoLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::Level::Info || self.verbose
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let log_line = self.format_log_line(record);

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