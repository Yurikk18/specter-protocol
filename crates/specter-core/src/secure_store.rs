//! Secure storage — encrypts wallet secrets at rest.
//!
//! Uses:
//! - Argon2id for passphrase-based key derivation (memory-hard, GPU-resistant)
//! - ChaCha20-Poly1305 for authenticated encryption
//! - Zeroize for wiping secrets from memory on drop

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// An encrypted blob with its nonce and salt.
#[derive(Clone, Debug)]
pub struct EncryptedData {
    /// Argon2 salt (16 bytes).
    pub salt: [u8; 16],
    /// ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: [u8; 12],
    /// Ciphertext + authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Derive an encryption key from a passphrase using Argon2id.
fn derive_key(passphrase: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let params = argon2::Params::new(
        65536,  // 64 MB memory
        3,      // 3 iterations
        1,      // 1 lane (parallelism)
        Some(32), // 32-byte output
    )
    .expect("valid argon2 params");

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .expect("argon2 hash failed");
    key
}

/// Encrypt data with a passphrase.
pub fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> EncryptedData {
    // Generate random salt and nonce
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Derive key
    let mut key = derive_key(passphrase, &salt);

    // Encrypt
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failed");

    // Zeroize key from memory
    key.zeroize();

    EncryptedData {
        salt,
        nonce: nonce_bytes,
        ciphertext,
    }
}

/// Decrypt data with a passphrase.
pub fn decrypt(encrypted: &EncryptedData, passphrase: &[u8]) -> Result<Vec<u8>, SecureStoreError> {
    let mut key = derive_key(passphrase, &encrypted.salt);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&encrypted.nonce);
    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| SecureStoreError::DecryptionFailed)?;

    key.zeroize();
    Ok(plaintext)
}

/// Compute a fingerprint of the encrypted data (for display, not security).
pub fn fingerprint(data: &EncryptedData) -> String {
    let hash = Sha256::digest(&data.ciphertext);
    hex::encode(&hash[..8])
}

/// Errors for secure storage.
#[derive(Debug, thiserror::Error)]
pub enum SecureStoreError {
    #[error("decryption failed — wrong passphrase or corrupted data")]
    DecryptionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = b"secret wallet data with private keys";
        let passphrase = b"my-strong-passphrase-123";

        let encrypted = encrypt(data, passphrase);
        let decrypted = decrypt(&encrypted, passphrase).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let data = b"secret data";
        let encrypted = encrypt(data, b"correct-passphrase");
        let result = decrypt(&encrypted, b"wrong-passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let data = b"secret data";
        let mut encrypted = encrypt(data, b"passphrase");
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }
        let result = decrypt(&encrypted, b"passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_plaintexts_different_ciphertexts() {
        let e1 = encrypt(b"data one", b"pass");
        let e2 = encrypt(b"data two", b"pass");
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    #[test]
    fn test_same_plaintext_different_ciphertexts() {
        // Random salt + nonce means same input produces different ciphertext
        let e1 = encrypt(b"same data", b"pass");
        let e2 = encrypt(b"same data", b"pass");
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    #[test]
    fn test_empty_plaintext() {
        let encrypted = encrypt(b"", b"pass");
        let decrypted = decrypt(&encrypted, b"pass").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext() {
        let data = vec![0x42u8; 10_000];
        let encrypted = encrypt(&data, b"pass");
        let decrypted = decrypt(&encrypted, b"pass").unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_fingerprint() {
        let encrypted = encrypt(b"data", b"pass");
        let fp = fingerprint(&encrypted);
        assert_eq!(fp.len(), 16); // 8 bytes hex = 16 chars
    }
}
