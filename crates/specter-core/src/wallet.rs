//! Wallet - manages multiple Proof-Carrying Tokens.
//!
//! Provides balance tracking, token selection for spending, and
//! storage management.

use crate::token::ProofCarryingToken;

/// A wallet holding multiple Proof-Carrying Tokens.
pub struct Wallet {
    tokens: Vec<ProofCarryingToken>,
}

impl Wallet {
    /// Create an empty wallet.
    pub fn new() -> Self {
        Self { tokens: Vec::new() }
    }

    /// Maximum tokens per wallet (DoS protection).
    const MAX_TOKENS: usize = 100_000;

    /// Add a token to the wallet.
    ///
    /// Returns false if the wallet is at capacity (MAX_TOKENS).
    pub fn add_token(&mut self, token: ProofCarryingToken) -> bool {
        if self.tokens.len() >= Self::MAX_TOKENS {
            return false;
        }
        self.tokens.push(token);
        true
    }

    /// Remove a token by its ID. Returns the removed token if found.
    pub fn remove_token(&mut self, token_id: &[u8; 32]) -> Option<ProofCarryingToken> {
        if let Some(pos) = self.tokens.iter().position(|t| &t.token_id == token_id) {
            Some(self.tokens.remove(pos))
        } else {
            None
        }
    }

    /// Total balance across all tokens (saturating to prevent overflow).
    pub fn balance(&self) -> u64 {
        self.tokens.iter().map(|t| t.value).fold(0u64, |acc, v| acc.saturating_add(v))
    }

    /// Number of tokens in the wallet.
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    /// Select the best token for spending a given amount (reference only).
    ///
    /// Strategy: smallest token that covers the amount and has
    /// remaining transfer capacity (not needing renewal).
    pub fn select_token(&self, amount: u64) -> Option<&ProofCarryingToken> {
        self.tokens
            .iter()
            .filter(|t| t.value >= amount && !t.needs_renewal())
            .min_by_key(|t| t.value)
    }

    /// Select and remove the best token for spending (takes ownership).
    ///
    /// This is the primary way to obtain a token for transfer, since
    /// ProofCarryingToken is non-Clone by design.
    pub fn take_token(&mut self, amount: u64) -> Option<ProofCarryingToken> {
        let idx = self.tokens
            .iter()
            .enumerate()
            .filter(|(_, t)| t.value >= amount && !t.needs_renewal())
            .min_by_key(|(_, t)| t.value)
            .map(|(i, _)| i)?;
        Some(self.tokens.remove(idx))
    }

    /// Get all tokens that need renewal (exceeded transfer bound).
    pub fn tokens_needing_renewal(&self) -> Vec<&ProofCarryingToken> {
        self.tokens.iter().filter(|t| t.needs_renewal()).collect()
    }

    /// Get all tokens with their basic info.
    pub fn list_tokens(&self) -> Vec<TokenInfo> {
        self.tokens
            .iter()
            .map(|t| TokenInfo {
                token_id: t.token_id,
                value: t.value,
                transfer_count: t.transfer_count,
                recursion_bound: t.recursion_bound,
                needs_renewal: t.needs_renewal(),
                has_credential: t.has_credential(),
                has_bond: t.has_bond(),
                estimated_size: t.estimated_size(),
            })
            .collect()
    }

    /// Total estimated storage size of all tokens.
    pub fn total_storage_bytes(&self) -> usize {
        self.tokens.iter().map(|t| t.estimated_size()).sum()
    }

    /// Check if the wallet is empty.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Save the wallet to encrypted bytes.
    ///
    /// All tokens are serialized and then encrypted with the passphrase
    /// using Argon2id + ChaCha20-Poly1305. The output is safe to write to disk.
    ///
    /// Returns an error if the passphrase fails validation (currently:
    /// shorter than `secure_store::MIN_PASSPHRASE_LEN`). Previously this
    /// panicked via `.expect()` — a malicious caller (or a misconfigured
    /// CLI) could crash the process with a short passphrase.
    pub fn save(&self, passphrase: &[u8]) -> Result<Vec<u8>, WalletError> {
        // Serialize all tokens
        let mut payload = Vec::new();
        let count = self.tokens.len() as u32;
        payload.extend_from_slice(&count.to_le_bytes());

        for token in &self.tokens {
            let token_bytes = crate::serde_token::serialize_token(token);
            let len = token_bytes.len() as u32;
            payload.extend_from_slice(&len.to_le_bytes());
            payload.extend_from_slice(&token_bytes);
        }

        // Encrypt the entire payload
        let encrypted = crate::secure_store::encrypt(&payload, passphrase)
            .map_err(|e| WalletError::TokenError(e.to_string()))?;

        // Pack EncryptedData into a single byte vector
        let mut output = Vec::new();
        output.extend_from_slice(b"SWLT"); // Specter WaLleT magic
        output.extend_from_slice(&encrypted.salt);
        output.extend_from_slice(&encrypted.nonce);
        let ct_len = encrypted.ciphertext.len() as u32;
        output.extend_from_slice(&ct_len.to_le_bytes());
        output.extend_from_slice(&encrypted.ciphertext);
        Ok(output)
    }

    /// Load a wallet from encrypted bytes and verify every token.
    ///
    /// Decrypts with the passphrase, deserializes all tokens,
    /// and verifies each one against the mint's public key.
    /// Rejects any token that fails verification (tampered or forged).
    pub fn load(
        data: &[u8],
        passphrase: &[u8],
        group_public_key: &curve25519_dalek::RistrettoPoint,
        pedersen: &specter_primitives::pedersen::PedersenParams,
        credential_pedersen: &specter_primitives::pedersen::PedersenParams,
        current_time: u64,
    ) -> Result<Self, WalletError> {
        if data.len() < 36 || &data[0..4] != b"SWLT" {
            return Err(WalletError::InvalidFormat);
        }

        let mut pos = 4;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[pos..pos + 16]);
        pos += 16;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[pos..pos + 12]);
        pos += 12;
        let ct_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        if pos + ct_len > data.len() {
            return Err(WalletError::InvalidFormat);
        }
        let ciphertext = data[pos..pos + ct_len].to_vec();

        let encrypted = crate::secure_store::EncryptedData {
            salt,
            nonce,
            ciphertext,
        };

        let payload = crate::secure_store::decrypt(&encrypted, passphrase)
            .map_err(|_| WalletError::WrongPassphrase)?;

        // Parse tokens from payload
        if payload.len() < 4 {
            return Err(WalletError::InvalidFormat);
        }
        let count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
        const MAX_TOKENS_PER_WALLET: usize = 100_000;
        if count > MAX_TOKENS_PER_WALLET {
            return Err(WalletError::InvalidFormat);
        }
        let mut offset = 4;
        let mut tokens = Vec::with_capacity(count);

        for _ in 0..count {
            if offset + 4 > payload.len() {
                return Err(WalletError::InvalidFormat);
            }
            let len = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + len > payload.len() {
                return Err(WalletError::InvalidFormat);
            }
            let token = crate::serde_token::deserialize_token(&payload[offset..offset + len])
                .map_err(|e| WalletError::TokenError(e.to_string()))?;

            // Verify the token before accepting it into the wallet.
            // Pass current_time so expired credentials are caught at load.
            let vr = crate::verify::verify_token(
                &token,
                group_public_key,
                pedersen,
                credential_pedersen,
                current_time,
            );
            if !vr.all_valid() {
                return Err(WalletError::TokenVerificationFailed);
            }

            tokens.push(token);
            offset += len;
        }

        Ok(Self { tokens })
    }
}

/// Errors for wallet operations.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("invalid wallet file format")]
    InvalidFormat,

    #[error("token verification failed: forged or tampered token")]
    TokenVerificationFailed,

    #[error("wrong passphrase or corrupted data")]
    WrongPassphrase,

    #[error("token deserialization failed: {0}")]
    TokenError(String),
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary info for a token in the wallet.
#[derive(Debug)]
pub struct TokenInfo {
    pub token_id: [u8; 32],
    pub value: u64,
    pub transfer_count: u32,
    pub recursion_bound: u32,
    pub needs_renewal: bool,
    pub has_credential: bool,
    pub has_bond: bool,
    pub estimated_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{Mint, MintConfig};
    use crate::transfer;

    fn setup_mint() -> Mint {
        Mint::setup(MintConfig {
            threshold: 2,
            total_signers: 3,
            recursion_bound: 5,
        })
    }

    #[test]
    fn test_empty_wallet() {
        let wallet = Wallet::new();
        assert!(wallet.is_empty());
        assert_eq!(wallet.balance(), 0);
        assert_eq!(wallet.token_count(), 0);
    }

    #[test]
    fn test_add_and_balance() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(200, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(500, &[1, 2], None).unwrap());

        assert_eq!(wallet.balance(), 800);
        assert_eq!(wallet.token_count(), 3);
    }

    #[test]
    fn test_select_token_smallest_fit() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(500, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(1000, &[1, 2], None).unwrap());

        // Should select 500 (smallest that covers 400)
        let selected = wallet.select_token(400).unwrap();
        assert_eq!(selected.value, 500);

        // Should select 100 (exact match)
        let selected = wallet.select_token(100).unwrap();
        assert_eq!(selected.value, 100);

        // No token covers 2000
        assert!(wallet.select_token(2000).is_none());
    }

    #[test]
    fn test_select_skips_renewal_needed() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        let token = mint.issue(100, &[1, 2], None).unwrap();
        // Transfer 5 times to reach bound
        let mut ns = crate::nullifier::NullifierSet::new();
        let mut current = token;
        for _ in 0..5 {
            current = transfer::transfer(current, &mut ns).unwrap().token;
        }
        wallet.add_token(current); // needs renewal

        wallet.add_token(mint.issue(500, &[1, 2], None).unwrap());

        // Should select 500 (100 needs renewal)
        let selected = wallet.select_token(50).unwrap();
        assert_eq!(selected.value, 500);
    }

    #[test]
    fn test_remove_token() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        let token = mint.issue(100, &[1, 2], None).unwrap();
        let id = token.token_id;
        wallet.add_token(token);

        assert_eq!(wallet.token_count(), 1);
        let removed = wallet.remove_token(&id).unwrap();
        assert_eq!(removed.value, 100);
        assert!(wallet.is_empty());
    }

    #[test]
    fn test_tokens_needing_renewal() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        // Fresh token
        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());

        // Exhausted token
        let token = mint.issue(200, &[1, 2], None).unwrap();
        let mut ns = crate::nullifier::NullifierSet::new();
        let mut current = token;
        for _ in 0..5 {
            current = transfer::transfer(current, &mut ns).unwrap().token;
        }
        wallet.add_token(current);

        let needing = wallet.tokens_needing_renewal();
        assert_eq!(needing.len(), 1);
        assert_eq!(needing[0].value, 200);
    }

    #[test]
    fn test_list_tokens() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(200, &[1, 2], None).unwrap());

        let list = wallet.list_tokens();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].value, 100);
        assert_eq!(list[1].value, 200);
    }

    #[test]
    fn test_total_storage() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(200, &[1, 2], None).unwrap());

        assert!(wallet.total_storage_bytes() > 0);
    }

    // ─── Save/Load tests ────────────────────────────────────────────

    fn load_wallet(mint: &Mint, data: &[u8], pass: &[u8]) -> Result<Wallet, WalletError> {
        Wallet::load(data, pass, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0)
    }

    #[test]
    fn test_save_load_roundtrip() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();
        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());
        wallet.add_token(mint.issue(500, &[1, 2], None).unwrap());

        let data = wallet.save(b"my-passphrase-min12").unwrap();
        let loaded = load_wallet(&mint, &data, b"my-passphrase-min12").unwrap();

        assert_eq!(loaded.balance(), 600);
        assert_eq!(loaded.token_count(), 2);
    }

    #[test]
    fn test_save_load_wrong_passphrase() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();
        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());

        let data = wallet.save(b"correct-pass12").unwrap();
        let result = load_wallet(&mint, &data, b"wrong-mn12-xx");
        assert!(result.is_err());
    }

    #[test]
    fn test_save_load_empty_wallet() {
        let mint = setup_mint();
        let wallet = Wallet::new();
        let data = wallet.save(b"pass-min12-ok").unwrap();
        let loaded = load_wallet(&mint, &data, b"pass-min12-ok").unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_save_load_preserves_token_values() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();

        let token = mint.issue(999, &[1, 2], None).unwrap();
        let original_id = token.token_id;
        wallet.add_token(token);

        let data = wallet.save(b"pass-min12-ok").unwrap();
        let loaded = load_wallet(&mint, &data, b"pass-min12-ok").unwrap();

        let info = loaded.list_tokens();
        assert_eq!(info[0].value, 999);
        assert_eq!(info[0].token_id, original_id);
    }

    #[test]
    fn test_save_load_tampered_data_fails() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();
        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());

        let mut data = wallet.save(b"pass-min12-ok").unwrap();
        if data.len() > 40 {
            data[40] ^= 0xFF;
        }
        let result = load_wallet(&mint, &data, b"pass-min12-ok");
        assert!(result.is_err());
    }

    #[test]
    fn test_save_rejects_short_passphrase() {
        let mint = setup_mint();
        let mut wallet = Wallet::new();
        wallet.add_token(mint.issue(100, &[1, 2], None).unwrap());

        // Short passphrase must return an error, NOT panic.
        let result = wallet.save(b"short");
        assert!(result.is_err(), "short passphrase must fail gracefully");
    }
}
