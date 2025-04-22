use std::path::Path;
use std::fs;
use tar::{Builder, Archive};
use flate2::{Compression, write::GzEncoder, read::GzDecoder};
use walkdir::WalkDir;
use crate::error::CryptoError;

pub fn create_archive(src_path: &Path) -> Result<Vec<u8>, CryptoError> {
    let mut archive_data = Vec::new();
    {
        let enc = GzEncoder::new(&mut archive_data, Compression::default());
        let mut builder = Builder::new(enc);

        for entry in WalkDir::new(src_path) {
            let entry = entry?; // Теперь это будет работать
            if entry.file_type().is_file() {
                builder.append_path_with_name(
                    entry.path(),
                    entry.path().strip_prefix(src_path)?
                )?;
            }
        }
        builder.finish()?;
    }
    Ok(archive_data)
}

pub fn extract_archive(data: &[u8], dest_path: &Path) -> Result<(), CryptoError> {
    if data.starts_with(&[0x1F, 0x8B]) {
        let decoder = GzDecoder::new(data);
        let mut archive = Archive::new(decoder);
        fs::create_dir_all(dest_path)?;
        archive.unpack(dest_path)?;
    } else {
        fs::write(dest_path, data)?;
    }
    Ok(())
}

// pub fn ensure_dir_exists(path: &str) -> io::Result<()> {
//     if !Path::new(path).exists() {
//         fs::create_dir_all(path)?;
//     }
//     Ok(())
// }

// pub fn is_likely_archive(data: &[u8]) -> bool {
//     // Проверка на GZIP архив
//     data.len() > 2 && data[0] == 0x1F && data[1] == 0x8B
// }