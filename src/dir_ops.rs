use crate::error::{Result, VaultError};
use crate::file_ops;
use crate::name_encrypt;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub fn encrypt_directory(root: &Path, password: &[u8]) -> Result<Vec<std::path::PathBuf>> {
    let exe_path = std::env::current_exe().unwrap_or_default();
    let mut processed = Vec::new();

    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();

    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path().to_path_buf();
        if path == exe_path {
            continue;
        }
        if entry.file_type().is_file() {
            files.push(path);
        } else if entry.file_type().is_dir() && path != root {
            dirs.push(path);
        }
    }

    // Sort files deepest first (bottom-up) so that encrypted file names
    // in deeper directories don't break parent path references.
    files.sort_by(|a, b| b.components().count().cmp(&a.components().count()));

    for path in &files {
        if !file_ops::is_encrypted(path) {
            file_ops::encrypt_file(path, password)?;
            processed.push(path.clone());
        }
    }

    // Sort directories deepest first (bottom-up) so renaming a child
    // doesn't invalidate the parent path.
    dirs.sort_by(|a, b| b.components().count().cmp(&a.components().count()));

    for dir in &dirs {
        let name = dir
            .file_name()
            .ok_or_else(|| {
                VaultError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "no dirname",
                ))
            })?
            .to_string_lossy()
            .to_string();
        let enc_name = name_encrypt::encrypt_dir_name(password, &name);
        let parent = dir.parent().unwrap_or(root);
        let new_path = parent.join(&enc_name);
        fs::rename(dir, &new_path)?;
        processed.push(dir.clone());
    }

    Ok(processed)
}

pub fn decrypt_directory(root: &Path, password: &[u8]) -> Result<Vec<std::path::PathBuf>> {
    let exe_path = std::env::current_exe().unwrap_or_default();
    let mut processed = Vec::new();

    // First pass: rename directories top-down (shallowest first) so
    // that after decrypting a parent directory name, the child paths
    // under the original (encrypted) name are still valid.
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path().to_path_buf();
        if entry.file_type().is_dir() && path != root {
            dirs.push(path);
        }
    }
    dirs.sort_by(|a, b| a.components().count().cmp(&b.components().count()));

    for dir in &dirs {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|s| name_encrypt::decrypt_dir_name(password, s));

        if let Some(orig_name) = name {
            let parent = dir.parent().unwrap_or(root);
            let orig_path = parent.join(&orig_name);
            fs::rename(dir, &orig_path)?;
            processed.push(dir.clone());
        }
    }

    // Second pass: decrypt all encrypted files.
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path().to_path_buf();
        if path == exe_path {
            continue;
        }
        if entry.file_type().is_file() && file_ops::is_encrypted(&path) {
            files.push(path);
        }
    }

    for path in &files {
        file_ops::decrypt_file(path, password)?;
        processed.push(path.clone());
    }

    Ok(processed)
}

pub fn has_encrypted_files(root: &Path) -> bool {
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && file_ops::is_encrypted(entry.path()) {
            return true;
        }
    }
    false
}

pub fn count_files(root: &Path) -> usize {
    let exe_path = std::env::current_exe().unwrap_or_default();
    WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && e.path() != exe_path)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("vault_dir_test_{}", name))
    }

    fn setup(name: &str) {
        let dir = temp_dir(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("子目录1")).unwrap();
        fs::create_dir_all(dir.join("子目录2")).unwrap();
        fs::write(dir.join("file1.txt"), b"content1").unwrap();
        fs::write(dir.join("子目录1/file2.txt"), b"content2").unwrap();
        fs::write(dir.join("子目录2/file3.txt"), b"content3").unwrap();
    }

    fn cleanup(name: &str) {
        let _ = fs::remove_dir_all(temp_dir(name));
    }

    #[test]
    fn test_encrypt_decrypt_directory() {
        let name = "enc_dec";
        setup(name);
        let dir = temp_dir(name);

        assert!(dir.join("file1.txt").exists());
        assert!(dir.join("子目录1/file2.txt").exists());

        encrypt_directory(&dir, b"password").unwrap();

        assert!(!dir.join("file1.txt").exists());
        assert!(!dir.join("子目录1").exists());
        assert!(has_encrypted_files(&dir));

        decrypt_directory(&dir, b"password").unwrap();

        assert!(dir.join("file1.txt").exists());
        assert!(dir.join("子目录1/file2.txt").exists());
        assert!(dir.join("子目录2/file3.txt").exists());

        assert_eq!(fs::read(dir.join("file1.txt")).unwrap(), b"content1");
        assert_eq!(fs::read(dir.join("子目录1/file2.txt")).unwrap(), b"content2");
        assert_eq!(
            fs::read(dir.join("子目录2/file3.txt")).unwrap(),
            b"content3"
        );

        cleanup(name);
    }

    #[test]
    fn test_count_files() {
        let name = "count";
        setup(name);
        assert_eq!(count_files(&temp_dir(name)), 3);
        cleanup(name);
    }

    #[test]
    fn test_has_encrypted_files_false() {
        let name = "has_enc";
        setup(name);
        assert!(!has_encrypted_files(&temp_dir(name)));
        cleanup(name);
    }
}
