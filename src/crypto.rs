use aes::Aes256;
use ctr::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher, StreamCipherSeek};
use ctr::Ctr32BE;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

type Aes256Ctr = Ctr32BE<Aes256>;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const SALT_LEN: usize = 16;
pub const PBKDF2_ITERATIONS: u32 = 100_000;
pub const HEAD_SIZE: usize = 64 * 1024;
pub const TAIL_SIZE: usize = 64 * 1024;
pub const SMALL_FILE_THRESHOLD: usize = 128 * 1024;

pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password, salt, PBKDF2_ITERATIONS, &mut key);
    key
}

pub fn apply_ctr(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    let mut cipher = Aes256Ctr::new(key.into(), GenericArray::from_slice(nonce));
    cipher.apply_keystream(data);
}

pub fn apply_ctr_from(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], offset: u64, data: &mut [u8]) {
    let mut cipher = Aes256Ctr::new(key.into(), GenericArray::from_slice(nonce));
    cipher.seek(offset);
    cipher.apply_keystream(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test_password";
        let salt = [0xABu8; SALT_LEN];
        let key1 = derive_key(password, &salt);
        let key2 = derive_key(password, &salt);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = [0xCDu8; SALT_LEN];
        let key1 = derive_key(b"password1", &salt);
        let key2 = derive_key(b"password2", &salt);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_ctr_round_trip() {
        let mut rng = rand::thread_rng();
        let mut key = [0u8; KEY_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);

        let original = b"Hello, World! This is a test of AES-256-CTR encryption.".to_vec();
        let mut data = original.clone();

        apply_ctr(&key, &nonce, &mut data);
        assert_ne!(data, original);

        apply_ctr(&key, &nonce, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_ctr_from_offset() {
        let mut rng = rand::thread_rng();
        let mut key = [0u8; KEY_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);

        let mut full_data = vec![0u8; 256 * 1024];
        rand::thread_rng().fill_bytes(&mut full_data);
        let original = full_data.clone();

        // Encrypt full buffer as reference
        let mut method1 = full_data.clone();
        apply_ctr(&key, &nonce, &mut method1);

        // Encrypt head and tail separately (with seek for tail)
        let mut method2 = full_data.clone();
        let tail_start = full_data.len() - TAIL_SIZE;
        apply_ctr(&key, &nonce, &mut method2[..HEAD_SIZE]);
        apply_ctr_from(&key, &nonce, tail_start as u64, &mut method2[tail_start..]);

        // Head and tail must match the full-encryption reference
        assert_eq!(method1[..HEAD_SIZE], method2[..HEAD_SIZE]);
        assert_eq!(method1[tail_start..], method2[tail_start..]);

        // Decrypt head and tail to recover original
        apply_ctr(&key, &nonce, &mut method2[..HEAD_SIZE]);
        apply_ctr_from(&key, &nonce, tail_start as u64, &mut method2[tail_start..]);
        assert_eq!(method2[..HEAD_SIZE], original[..HEAD_SIZE]);
        assert_eq!(method2[tail_start..], original[tail_start..]);
    }

    #[test]
    fn test_ctr_different_nonces() {
        let key = [0x42u8; KEY_LEN];
        let mut nonce1 = [0u8; NONCE_LEN];
        let mut nonce2 = [0u8; NONCE_LEN];
        nonce1[0] = 1;
        nonce2[0] = 2;

        let data = b"same input data";
        let mut enc1 = data.to_vec();
        let mut enc2 = data.to_vec();

        apply_ctr(&key, &nonce1, &mut enc1);
        apply_ctr(&key, &nonce2, &mut enc2);

        assert_ne!(enc1, enc2);
    }
}
