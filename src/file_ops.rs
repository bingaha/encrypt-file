use crate::crypto::{self, HEAD_SIZE, TAIL_SIZE, SMALL_FILE_THRESHOLD};
use crate::error::{Result, VaultError};
use crate::metadata::FileMetadata;
use crate::name_encrypt;
use filetime::FileTime;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub fn encrypt_file(path: &Path, password: &[u8]) -> Result<()> {
    let metadata = fs::metadata(path)?;
    let orig_size = metadata.len();
    let orig_mtime = FileTime::from_last_modification_time(&metadata).unix_seconds();
    let orig_name = path
        .file_name()
        .ok_or_else(|| {
            VaultError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no filename",
            ))
        })?
        .to_string_lossy()
        .to_string();

    let fm = FileMetadata::new(orig_name, orig_size, orig_mtime);
    let key = crypto::derive_key(password, &fm.salt);

    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;

    if orig_size as usize <= SMALL_FILE_THRESHOLD {
        // Small file: encrypt entire content
        let mut buf = vec![0u8; orig_size as usize];
        file.read_exact(&mut buf)?;
        crypto::apply_ctr(&key, &fm.nonce, &mut buf);
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&buf)?;
    } else {
        // Large file: encrypt head
        let mut head = vec![0u8; HEAD_SIZE];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut head)?;
        crypto::apply_ctr(&key, &fm.nonce, &mut head);
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&head)?;

        // Encrypt tail
        let tail_offset = orig_size - TAIL_SIZE as u64;
        let mut tail = vec![0u8; TAIL_SIZE];
        file.seek(SeekFrom::Start(tail_offset))?;
        file.read_exact(&mut tail)?;
        crypto::apply_ctr_from(&key, &fm.nonce, tail_offset, &mut tail);
        file.seek(SeekFrom::Start(tail_offset))?;
        file.write_all(&tail)?;
    }

    // Append metadata block
    let meta_bytes = fm.to_bytes(password);
    file.seek(SeekFrom::End(0))?;
    file.write_all(&meta_bytes)?;
    file.sync_all()?;
    drop(file);

    // Rename to encrypted name
    let parent = path.parent().unwrap_or(path);
    let enc_name = name_encrypt::encrypt_file_name(password, &fm.orig_name);
    let enc_path = parent.join(&enc_name);
    fs::rename(path, &enc_path)?;

    Ok(())
}

pub fn decrypt_file(path: &Path, password: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;

    let fm = FileMetadata::read_from_file(&mut file, password).ok_or(VaultError::InvalidPassword)?;

    let key = crypto::derive_key(password, &fm.salt);

    if fm.orig_size as usize <= SMALL_FILE_THRESHOLD {
        let meta_len = FileMetadata::detect(&mut file)
            .ok_or_else(|| VaultError::CorruptedMetadata(path.to_path_buf()))?;
        let content_len = file.metadata()?.len() - meta_len as u64;
        let mut buf = vec![0u8; content_len as usize];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut buf)?;
        crypto::apply_ctr(&key, &fm.nonce, &mut buf);
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&buf)?;
        file.set_len(fm.orig_size)?;
    } else {
        let mut head = vec![0u8; HEAD_SIZE];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut head)?;
        crypto::apply_ctr(&key, &fm.nonce, &mut head);
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&head)?;

        let tail_offset = fm.orig_size - TAIL_SIZE as u64;
        let mut tail = vec![0u8; TAIL_SIZE];
        file.seek(SeekFrom::Start(tail_offset))?;
        file.read_exact(&mut tail)?;
        crypto::apply_ctr_from(&key, &fm.nonce, tail_offset, &mut tail);
        file.seek(SeekFrom::Start(tail_offset))?;
        file.write_all(&tail)?;

        file.set_len(fm.orig_size)?;
    }

    file.sync_all()?;
    drop(file);

    let mtime = FileTime::from_unix_time(fm.orig_mtime, 0);
    filetime::set_file_mtime(path, mtime)?;

    let parent = path.parent().unwrap_or(path);
    let orig_path = parent.join(&fm.orig_name);
    fs::rename(path, &orig_path)?;

    Ok(())
}

pub fn is_encrypted(path: &Path) -> bool {
    if let Ok(mut file) = fs::File::open(path) {
        FileMetadata::detect(&mut file).is_some()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("vault_test_{}", name))
    }

    fn setup(name: &str) {
        let dir = test_dir(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
    }

    fn cleanup(name: &str) {
        let _ = fs::remove_dir_all(test_dir(name));
    }

    fn find_encrypted_file(dir: &Path) -> std::path::PathBuf {
        fs::read_dir(dir)
            .unwrap()
            .find(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".dat")
            })
            .unwrap()
            .unwrap()
            .path()
    }

    #[test]
    fn test_encrypt_decrypt_large_file() {
        let name = "large_file";
        setup(name);
        let dir = test_dir(name);
        let path = dir.join("large_test.bin");
        let original_data: Vec<u8> = (0..256 * 1024).map(|i| (i % 256) as u8).collect();
        fs::write(&path, &original_data).unwrap();

        let orig_size = fs::metadata(&path).unwrap().len();

        encrypt_file(&path, b"password").unwrap();
        assert!(!path.exists());

        let enc_path = find_encrypted_file(&dir);
        assert!(fs::metadata(&enc_path).unwrap().len() > orig_size);
        let enc_data = fs::read(&enc_path).unwrap();
        assert_ne!(&enc_data[..256], &original_data[..256]);

        decrypt_file(&enc_path, b"password").unwrap();
        assert!(path.exists());
        let restored = fs::read(&path).unwrap();
        assert_eq!(restored, original_data);

        cleanup(name);
    }

    #[test]
    fn test_encrypt_decrypt_small_file() {
        let name = "small_file";
        setup(name);
        let dir = test_dir(name);
        let path = dir.join("small.txt");
        fs::write(&path, b"Hello, World!").unwrap();

        encrypt_file(&path, b"password").unwrap();
        let enc_path = find_encrypted_file(&dir);

        decrypt_file(&enc_path, b"password").unwrap();
        let restored = fs::read(&path).unwrap();
        assert_eq!(restored, b"Hello, World!");

        cleanup(name);
    }

    #[test]
    fn test_encrypt_decrypt_empty_file() {
        let name = "empty_file";
        setup(name);
        let dir = test_dir(name);
        let path = dir.join("empty.txt");
        fs::write(&path, b"").unwrap();

        encrypt_file(&path, b"password").unwrap();
        let enc_path = find_encrypted_file(&dir);

        decrypt_file(&enc_path, b"password").unwrap();
        let restored = fs::read(&path).unwrap();
        assert!(restored.is_empty());

        cleanup(name);
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let name = "wrong_pw";
        setup(name);
        let dir = test_dir(name);
        let path = dir.join("test.txt");
        fs::write(&path, b"secret data").unwrap();

        encrypt_file(&path, b"correct").unwrap();
        let enc_path = find_encrypted_file(&dir);

        let result = decrypt_file(&enc_path, b"wrong");
        assert!(result.is_err());

        cleanup(name);
    }

    #[test]
    fn test_is_encrypted() {
        let name = "is_enc";
        setup(name);
        let dir = test_dir(name);
        let path = dir.join("test.txt");
        fs::write(&path, b"content").unwrap();

        assert!(!is_encrypted(&path));

        encrypt_file(&path, b"password").unwrap();
        let enc_path = find_encrypted_file(&dir);

        assert!(is_encrypted(&enc_path));

        cleanup(name);
    }
}
