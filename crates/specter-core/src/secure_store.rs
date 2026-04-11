//! Secure storage - encrypts wallet secrets at rest.
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
        131072, // 128 MB memory — financial-grade key derivation
        4,      // 4 iterations
        4,      // 4 lanes (parallelism) — forces 4x resources per brute-force attempt
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

/// Minimum passphrase length for encryption.
/// 12 bytes provides ~56 bits of entropy for random alphanumeric,
/// which combined with Argon2id at 128 MB resists offline brute-force.
pub const MIN_PASSPHRASE_LEN: usize = 12;

/// Encrypt data with a passphrase.
///
/// Returns an error if the passphrase is shorter than MIN_PASSPHRASE_LEN.
pub fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> Result<EncryptedData, SecureStoreError> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(SecureStoreError::PassphraseTooShort {
            min: MIN_PASSPHRASE_LEN,
            got: passphrase.len(),
        });
    }
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

    Ok(EncryptedData {
        salt,
        nonce: nonce_bytes,
        ciphertext,
    })
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
    #[error("decryption failed - wrong passphrase or corrupted data")]
    DecryptionFailed,

    #[error("passphrase too short: need at least {min} bytes, got {got}")]
    PassphraseTooShort { min: usize, got: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = b"secret wallet data with private keys";
        let passphrase = b"my-strong-passphrase-123";

        let encrypted = encrypt(data, passphrase).unwrap();
        let decrypted = decrypt(&encrypted, passphrase).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let data = b"secret data";
        let encrypted = encrypt(data, b"correct-passphrase").unwrap();
        let result = decrypt(&encrypted, b"wrong-passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let data = b"secret data";
        let mut encrypted = encrypt(data, b"passphrase-min12").unwrap();
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }
        let result = decrypt(&encrypted, b"passphrase-min12");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_plaintexts_different_ciphertexts() {
        let e1 = encrypt(b"data one", b"pass-min12-ok").unwrap();
        let e2 = encrypt(b"data two", b"pass-min12-ok").unwrap();
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    #[test]
    fn test_same_plaintext_different_ciphertexts() {
        // Random salt + nonce means same input produces different ciphertext
        let e1 = encrypt(b"same data", b"pass-min12-ok").unwrap();
        let e2 = encrypt(b"same data", b"pass-min12-ok").unwrap();
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    #[test]
    fn test_empty_plaintext() {
        let encrypted = encrypt(b"", b"pass-min12-ok").unwrap();
        let decrypted = decrypt(&encrypted, b"pass-min12-ok").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext() {
        let data = vec![0x42u8; 10_000];
        let encrypted = encrypt(&data, b"pass-min12-ok").unwrap();
        let decrypted = decrypt(&encrypted, b"pass-min12-ok").unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_short_passphrase_returns_error() {
        let result = encrypt(b"data", b"short");
        assert!(result.is_err());
    }

    #[test]
    fn test_fingerprint() {
        let encrypted = encrypt(b"data", b"pass-min12-ok").unwrap();
        let fp = fingerprint(&encrypted);
        assert_eq!(fp.len(), 16); // 8 bytes hex = 16 chars
    }
}
