//! Token minting (issuance) via threshold blind signatures.
//!
//! The Mint orchestrates the issuance of new Proof-Carrying Tokens.
//! It uses a threshold blind signature scheme so that no single signer
//! knows the token content, and the token can only be issued with
//! cooperation of t-of-n signers.

use curve25519_dalek::RistrettoPoint;

use specter_blind_sig::threshold::{self, SignerId, ThresholdKeyset};
use specter_primitives::pedersen::PedersenParams;
use specter_primitives::scalar_utils::{random_scalar, scalar_from_u64};

use crate::token::ProofCarryingToken;

/// Configuration for the mint.
pub struct MintConfig {
    /// Minimum signers required (threshold).
    pub threshold: usize,
    /// Total number of signers.
    pub total_signers: usize,
    /// Maximum transfers before token renewal.
    pub recursion_bound: u32,
}

/// The Mint: issues new Proof-Carrying Tokens.
pub struct Mint {
    pub keyset: ThresholdKeyset,
    pub pedersen: PedersenParams,
    pub recursion_bound: u32,
}

impl Mint {
    /// Set up a new mint with the given configuration.
    pub fn setup(config: MintConfig) -> Self {
        let keyset = threshold::dealer_keygen(config.threshold, config.total_signers);
        let pedersen = PedersenParams::new();
        Self {
            keyset,
            pedersen,
            recursion_bound: config.recursion_bound,
        }
    }

    /// Issue a new token with the given value.
    ///
    /// The specified signers participate in the threshold blind signature.
    /// The token is created with a fresh random ID, a Pedersen commitment
    /// to the value, and an initial hash chain.
    pub fn issue(
        &self,
        value: u64,
        signers: &[SignerId],
    ) -> Result<ProofCarryingToken, MintError> {
        // Generate random token ID
        let mut token_id = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut token_id);

        // Generate random owner secret
        let mut owner_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut owner_secret);

        // Create Pedersen commitment to the value
        let value_scalar = scalar_from_u64(value);
        let blinding = random_scalar();
        let value_commitment = self.pedersen.commit(&value_scalar, &blinding);

        // Compute the message to be signed: H(token_id || value_commitment)
        let signed_msg = build_signed_message(&token_id, &value_commitment);

        // Threshold blind sign
        let signature = threshold::threshold_blind_sign(&self.keyset, signers, &signed_msg)
            .map_err(|e| MintError::SigningFailed(e.to_string()))?;

        // Initial hash chain head = H("specter-genesis:" || token_id)
        let hash_chain_head = crate::token::advance_hash_chain(&[0u8; 32], &token_id);

        Ok(ProofCarryingToken {
            token_id,
            value,
            value_commitment,
            value_blinding: blinding,
            mint_signature: signature,
            owner_secret,
            hash_chain_head,
            transfer_count: 0,
            recursion_bound: self.recursion_bound,
        })
    }

    /// Get the group public key (used for verification).
    pub fn group_public_key(&self) -> RistrettoPoint {
        self.keyset.group_public
    }
}

/// Build the message that gets threshold-blind-signed.
pub fn build_signed_message(token_id: &[u8; 32], value_commitment: &RistrettoPoint) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(token_id);
    msg.extend_from_slice(value_commitment.compress().as_bytes());
    msg
}

/// Errors during minting.
#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify;

    fn test_mint() -> Mint {
        Mint::setup(MintConfig {
            threshold: 2,
            total_signers: 3,
            recursion_bound: 20,
        })
    }

    #[test]
    fn test_mint_issue() {
        let mint = test_mint();
        let token = mint.issue(1000, &[1, 2]).unwrap();

        assert_eq!(token.value, 1000);
        assert_eq!(token.transfer_count, 0);
        assert_eq!(token.recursion_bound, 20);
        assert!(!token.needs_renewal());
    }

    #[test]
    fn test_mint_different_signers() {
        let mint = test_mint();
        let t1 = mint.issue(100, &[1, 2]).unwrap();
        let t2 = mint.issue(100, &[2, 3]).unwrap();
        let t3 = mint.issue(100, &[1, 3]).unwrap();

        // All should have valid signatures (verified in verify tests)
        assert_ne!(t1.token_id, t2.token_id);
        assert_ne!(t2.token_id, t3.token_id);
    }

    #[test]
    fn test_mint_insufficient_signers() {
        let mint = test_mint();
        let result = mint.issue(100, &[1]); // need 2, only gave 1
        assert!(result.is_err());
    }

    #[test]
    fn test_mint_verify_roundtrip() {
        let mint = test_mint();
        let token = mint.issue(500, &[1, 3]).unwrap();

        let result = verify::verify_token(&token, &mint.group_public_key(), &mint.pedersen);
        assert!(result.signature_valid);
        assert!(result.value_valid);
        assert!(result.within_bound);
        assert!(result.all_valid());
    }
}
