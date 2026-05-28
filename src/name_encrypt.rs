use crate::crypto::{self, KEY_LEN, NONCE_LEN, SALT_LEN};

const NAME_SALT: [u8; SALT_LEN] = *b"VAULT_NAME_KEY_!"; // 16 bytes
const NAME_NONCE: [u8; NONCE_LEN] = [0u8; NONCE_LEN]; // fixed nonce for deterministic encryption (16 bytes)
const FILE_EXT: &str = ".dat";

fn derive_name_key(password: &[u8]) -> [u8; KEY_LEN] {
    crypto::derive_key(password, &NAME_SALT)
}

pub fn encrypt_file_name(password: &[u8], name: &str) -> String {
    let key = derive_name_key(password);
    let mut bytes = name.as_bytes().to_vec();
    crypto::apply_ctr(&key, &NAME_NONCE, &mut bytes);
    hex::encode(&bytes) + FILE_EXT
}

pub fn decrypt_file_name(password: &[u8], encrypted: &str) -> Option<String> {
    let without_ext = encrypted.strip_suffix(FILE_EXT)?;
    let bytes = hex::decode(without_ext).ok()?;
    let key = derive_name_key(password);
    let mut bytes = bytes;
    crypto::apply_ctr(&key, &NAME_NONCE, &mut bytes);
    String::from_utf8(bytes).ok()
}

pub fn encrypt_dir_name(password: &[u8], name: &str) -> String {
    let key = derive_name_key(password);
    let mut bytes = name.as_bytes().to_vec();
    crypto::apply_ctr(&key, &NAME_NONCE, &mut bytes);
    hex::encode(&bytes)
}

pub fn decrypt_dir_name(password: &[u8], encrypted: &str) -> Option<String> {
    let bytes = hex::decode(encrypted).ok()?;
    let key = derive_name_key(password);
    let mut bytes = bytes;
    crypto::apply_ctr(&key, &NAME_NONCE, &mut bytes);
    String::from_utf8(bytes).ok()
}

pub fn would_exceed_name_limit(name: &str, is_file: bool) -> bool {
    let enc_bytes = name.as_bytes().len();
    let hex_len = enc_bytes * 2;
    let ext_len = if is_file { FILE_EXT.len() } else { 0 };
    (hex_len + ext_len) > 240
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_name_round_trip() {
        let password = b"test_password";
        let original = "报告.pdf";
        let encrypted = encrypt_file_name(password, original);
        assert!(encrypted.ends_with(FILE_EXT));
        assert_ne!(encrypted, original);
        let decrypted = decrypt_file_name(password, &encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_dir_name_round_trip() {
        let password = b"test_password";
        let original = "工作文档";
        let encrypted = encrypt_dir_name(password, original);
        assert!(!encrypted.contains("."));
        let decrypted = decrypt_dir_name(password, &encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_chinese_filename() {
        let password = b"password";
        let name = "04-河南豫剧《三请樊梨花》02 开封市豫剧团演出-480P 清晰-AVC.mp4";
        let encrypted = encrypt_file_name(password, name);
        let decrypted = decrypt_file_name(password, &encrypted).unwrap();
        assert_eq!(decrypted, name);
    }

    #[test]
    fn test_long_english_filename() {
        let password = b"password";
        let name = "White.Snake.2019.WEB-DL.1080P&2160P.H264.AAC-FGTR[BTBus].mkv";
        let encrypted = encrypt_file_name(password, name);
        let decrypted = decrypt_file_name(password, &encrypted).unwrap();
        assert_eq!(decrypted, name);
    }

    #[test]
    fn test_wrong_password_returns_none() {
        let encrypted = encrypt_file_name(b"correct", "secret.txt");
        assert!(decrypt_file_name(b"wrong", &encrypted).is_none());
    }

    #[test]
    fn test_deterministic() {
        let password = b"test";
        let name = "file.txt";
        let enc1 = encrypt_file_name(password, name);
        let enc2 = encrypt_file_name(password, name);
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn test_would_exceed_name_limit_short() {
        assert!(!would_exceed_name_limit("short.txt", true));
    }

    #[test]
    fn test_would_exceed_name_limit_long() {
        let very_long = "x".repeat(200);
        assert!(would_exceed_name_limit(&very_long, true));
    }
}
