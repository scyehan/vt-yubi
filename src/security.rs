use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{ensure, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};

#[cfg(feature = "server")]
#[allow(dead_code)]
pub fn load_mac_cipher_from_yubikey(yk: &mut ::yubikey::YubiKey) -> Result<AesGcmCrypto> {
    let passphrase = crate::yk_backend::load_passphrase(yk)?;
    AesGcmCrypto::new(&passphrase)
}

#[cfg(feature = "server")]
#[allow(dead_code)]
pub fn load_ciphers_from_yubikey(
    yk: &mut ::yubikey::YubiKey,
) -> Result<(AesGcmCrypto, AesGcmCrypto)> {
    tracing::info!("Touch YubiKey to decrypt auth token...");
    let auth_token = crate::yk_backend::load_auth_token(yk)?;
    let auth_cipher = AesGcmCrypto::new(&auth_token)?;

    tracing::info!("Touch YubiKey to decrypt passphrase...");
    let passphrase = crate::yk_backend::load_passphrase(yk)?;
    let passphrase_cipher = AesGcmCrypto::new(&passphrase)?;

    Ok((auth_cipher, passphrase_cipher))
}

pub fn decode_auth_cipher_from_b64(b64_token: &str) -> Result<[u8; 32]> {
    let token_bytes = BASE64_URL_SAFE_NO_PAD.decode(b64_token)?;
    let hash = Sha256::digest(&Sha256::digest(token_bytes));
    let mut token = [0u8; 32];
    token.copy_from_slice(&hash[..32]);
    Ok(token)
}

pub struct AesGcmCrypto {
    cipher: Aes256Gcm,
}

impl AesGcmCrypto {
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        ensure!(key.len() == 32, "Invalid key length, expected 32 bytes");
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {e}"))?;
        Ok(Self { cipher })
    }

    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Encrypt data. The result contains nonce (first 12 bytes) and ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = Self::generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption error: {e}"))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data. Input should contain nonce (first 12 bytes) and ciphertext.
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        ensure!(encrypted_data.len() >= 12, "Data too short, missing nonce");
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption error: {e}"))?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        let text = b"to be encoded".to_vec();
        assert_eq!(BASE64_URL_SAFE_NO_PAD.encode(&text), "dG8gYmUgZW5jb2RlZA");
    }

    #[test]
    fn test_generation() {
        let key1 = AesGcmCrypto::generate_key();
        let key2 = AesGcmCrypto::generate_key();
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2);

        let nonce1 = AesGcmCrypto::generate_nonce();
        let nonce2 = AesGcmCrypto::generate_nonce();
        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce2.len(), 12);
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_encrypt_decrypt_basic() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = b"Hello, World!";

        let encrypted = crypto.encrypt(plaintext).unwrap();
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);

        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = b"";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = vec![0xAB; 1024 * 1024];
        let encrypted = crypto.encrypt(&plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_corrupted_data() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = b"Original message";
        let mut encrypted = crypto.encrypt(plaintext).unwrap();

        encrypted[15] ^= 0xFF;

        let result = crypto.decrypt(&encrypted);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Decryption error"));
    }

    #[test]
    fn test_multiple_encryptions_different_results() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = b"Same message";
        let encrypted1 = crypto.encrypt(plaintext).unwrap();
        let encrypted2 = crypto.encrypt(plaintext).unwrap();
        assert_ne!(encrypted1, encrypted2);

        let decrypted1 = crypto.decrypt(&encrypted1).unwrap();
        let decrypted2 = crypto.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
        assert_eq!(decrypted1, decrypted2);
    }

    #[test]
    fn test_unicode_text() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = "Hello, \u{4e16}\u{754c}! \u{1f30d}".as_bytes();
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        let decrypted_str = String::from_utf8(decrypted).unwrap();
        assert_eq!(decrypted_str, "Hello, \u{4e16}\u{754c}! \u{1f30d}");
    }
}
