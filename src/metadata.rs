use crate::crypto::{self, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{Result, VaultError};
use rand::RngCore;
use std::io::{self, Read, Seek, SeekFrom, Write};

pub const MAGIC: [u8; 4] = [0x56, 0x41, 0x4C, 0x54]; // "VALT"

#[derive(Debug)]
pub struct FileMetadata {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub meta_nonce: [u8; NONCE_LEN],
    pub orig_name: String,
    pub orig_size: u64,
    pub orig_mtime: i64,
}

impl FileMetadata {
    pub fn new(orig_name: String, orig_size: u64, orig_mtime: i64) -> Self {
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        let mut meta_nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);
        rng.fill_bytes(&mut meta_nonce);
        Self {
            salt,
            nonce,
            meta_nonce,
            orig_name,
            orig_size,
            orig_mtime,
        }
    }

    pub fn to_bytes(&self, password: &[u8]) -> Vec<u8> {
        let key = crypto::derive_key(password, &self.salt);

        let name_bytes = self.orig_name.as_bytes();
        let mut body = Vec::with_capacity(2 + name_bytes.len() + 8 + 8 + 4);
        body.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        body.extend_from_slice(name_bytes);
        body.extend_from_slice(&self.orig_size.to_le_bytes());
        body.extend_from_slice(&self.orig_mtime.to_le_bytes());

        let checksum = crc32fast::hash(&body);
        body.extend_from_slice(&checksum.to_le_bytes());

        crypto::apply_ctr(&key, &self.meta_nonce, &mut body);

        let mut out = Vec::with_capacity(4 + SALT_LEN + NONCE_LEN + NONCE_LEN + body.len() + 4);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.meta_nonce);
        out.extend_from_slice(&body);

        let meta_len = out.len() as u32 + 4;
        out.extend_from_slice(&meta_len.to_le_bytes());

        out
    }

    pub fn from_bytes(data: &[u8], password: &[u8]) -> Option<Self> {
        if data.len() < 4 + SALT_LEN + NONCE_LEN + NONCE_LEN + 4 {
            return None;
        }

        if data[0..4] != MAGIC {
            return None;
        }

        let salt: [u8; SALT_LEN] = data[4..20].try_into().ok()?;
        let nonce: [u8; NONCE_LEN] = data[20..20 + NONCE_LEN].try_into().ok()?;
        let meta_nonce: [u8; NONCE_LEN] = data[20 + NONCE_LEN..20 + NONCE_LEN * 2].try_into().ok()?;

        let key = crypto::derive_key(password, &salt);

        let body_start = 4 + SALT_LEN + NONCE_LEN + NONCE_LEN;
        let mut body = data[body_start..].to_vec();
        crypto::apply_ctr(&key, &meta_nonce, &mut body);

        if body.len() < 2 + 8 + 8 + 4 {
            return None;
        }

        let name_len = u16::from_le_bytes([body[0], body[1]]) as usize;
        if body.len() < 2 + name_len + 8 + 8 + 4 {
            return None;
        }

        let orig_name = String::from_utf8(body[2..2 + name_len].to_vec()).ok()?;
        let orig_size =
            u64::from_le_bytes(body[2 + name_len..10 + name_len].try_into().ok()?);
        let orig_mtime =
            i64::from_le_bytes(body[10 + name_len..18 + name_len].try_into().ok()?);
        let stored_checksum =
            u32::from_le_bytes(body[18 + name_len..22 + name_len].try_into().ok()?);

        let computed_checksum = crc32fast::hash(&body[..18 + name_len]);
        if stored_checksum != computed_checksum {
            return None;
        }

        Some(Self {
            salt,
            nonce,
            meta_nonce,
            orig_name,
            orig_size,
            orig_mtime,
        })
    }

    pub fn detect(file: &mut (impl Read + Seek)) -> Option<u32> {
        file.seek(SeekFrom::End(-4)).ok()?;
        let mut len_buf = [0u8; 4];
        file.read_exact(&mut len_buf).ok()?;
        let meta_len = u32::from_le_bytes(len_buf);

        let min_size = 4 + SALT_LEN + NONCE_LEN + NONCE_LEN + 22 + 4;
        if meta_len < min_size as u32 || meta_len > 10_000 {
            return None;
        }

        file.seek(SeekFrom::End(-(meta_len as i64))).ok()?;
        let mut magic_buf = [0u8; 4];
        file.read_exact(&mut magic_buf).ok()?;

        if magic_buf == MAGIC {
            Some(meta_len)
        } else {
            None
        }
    }

    pub fn read_from_file(file: &mut (impl Read + Seek), password: &[u8]) -> Option<Self> {
        let meta_len = Self::detect(file)?;
        file.seek(SeekFrom::End(-(meta_len as i64))).ok()?;
        let mut buf = vec![0u8; meta_len as usize];
        file.read_exact(&mut buf).ok()?;
        Self::from_bytes(&buf, password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_round_trip() {
        let password = b"test_password";
        let meta = FileMetadata::new("测试文件.txt".to_string(), 1024 * 1024, 1700000000);
        let bytes = meta.to_bytes(password);
        let parsed = FileMetadata::from_bytes(&bytes, password).unwrap();

        assert_eq!(parsed.orig_name, "测试文件.txt");
        assert_eq!(parsed.orig_size, 1024 * 1024);
        assert_eq!(parsed.orig_mtime, 1700000000);
        assert_eq!(parsed.salt, meta.salt);
        assert_eq!(parsed.nonce, meta.nonce);
        assert_eq!(parsed.meta_nonce, meta.meta_nonce);
    }

    #[test]
    fn test_metadata_wrong_password() {
        let password = b"correct_password";
        let meta = FileMetadata::new("file.pdf".to_string(), 5000, 1700000000);
        let bytes = meta.to_bytes(password);
        let result = FileMetadata::from_bytes(&bytes, b"wrong_password");
        assert!(result.is_none());
    }

    #[test]
    fn test_metadata_detect_valid() {
        let password = b"test";
        let meta = FileMetadata::new("test.txt".to_string(), 100, 1700000000);
        let bytes = meta.to_bytes(password);
        let padding_len = 1000 - bytes.len();
        let mut file_data = Vec::with_capacity(1000);
        file_data.extend_from_slice(&vec![0u8; padding_len]);
        file_data.extend_from_slice(&bytes);
        let mut file = io::Cursor::new(file_data);
        let detected_len = FileMetadata::detect(&mut file).unwrap();
        assert_eq!(detected_len as usize, bytes.len());
    }

    #[test]
    fn test_metadata_detect_invalid() {
        let mut file = io::Cursor::new(vec![0u8; 100]);
        assert!(FileMetadata::detect(&mut file).is_none());
    }

    #[test]
    fn test_metadata_long_filename() {
        let password = b"test";
        let long_name = "很长的文件名".repeat(20);
        let meta = FileMetadata::new(long_name.clone(), 999, 1700000000);
        let bytes = meta.to_bytes(password);
        let parsed = FileMetadata::from_bytes(&bytes, password).unwrap();
        assert_eq!(parsed.orig_name, long_name);
    }
}
