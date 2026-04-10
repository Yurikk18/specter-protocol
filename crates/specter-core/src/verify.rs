//! Unified token verification.
//!
//! Verifies all properties of a Proof-Carrying Token in a single call:
//! - Signature validity (threshold blind signature from the mint)
//! - Value commitment correctness
//! - Transfer count within recursion bound

use curve25519_dalek::RistrettoPoint;

use specter_blind_sig::schnorr_blind;
use specter_primitives::pedersen::PedersenParams;
use specter_primitives::scalar_utils::scalar_from_u64;

use crate::mint;
use crate::token::ProofCarryingToken;

/// Result of token verification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the mint's blind signature is valid.
    pub signature_valid: bool,
    /// Whether the value commitment matches the claimed value.
    pub value_valid: bool,
    /// Whether the transfer count is within the recursion bound.
    pub within_bound: bool,
}

impl VerificationResult {
    /// Returns true only if ALL checks passed.
    pub fn all_valid(&self) -> bool {
        self.signature_valid && self.value_valid && self.within_bound
    }
}

/// Verify a Proof-Carrying Token.
///
/// Checks:
/// 1. The blind signature from the mint is valid against the group public key.
/// 2. The Pedersen commitment to the value opens correctly.
/// 3. The transfer count has not exceeded the recursion bound.
pub fn verify_token(
    token: &ProofCarryingToken,
    group_public_key: &RistrettoPoint,
    pedersen: &PedersenParams,
) -> VerificationResult {
    // 1. Verify the mint's blind signature
    let signed_msg = mint::build_signed_message(&token.token_id, &token.value_commitment);
    let signature_valid = schnorr_blind::verify(group_public_key, &signed_msg, &token.mint_signature);

    // 2. Verify the value commitment
    let value_scalar = scalar_from_u64(token.value);
    let value_valid = pedersen.verify_opening(
        &token.value_commitment,
        &value_scalar,
        &token.value_blinding,
    );

    // 3. Check transfer count
    let within_bound = token.transfer_count <= token.recursion_bound;

    VerificationResult {
        signature_valid,
        value_valid,
        within_bound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{Mint, MintConfig};
    use crate::transfer;

    fn setup() -> Mint {
        Mint::setup(MintConfig {
            threshold: 2,
            total_signers: 3,
            recursion_bound: 20,
        })
    }

    #[test]
    fn test_freshly_minted_token_valid() {
        let mint = setup();
        let token = mint.issue(500, &[1, 2]).unwrap();
        let result = verify_token(&token, &mint.group_public_key(), &mint.pedersen);

        assert!(result.signature_valid);
        assert!(result.value_valid);
        assert!(result.within_bound);
        assert!(result.all_valid());
    }

    #[test]
    fn test_transferred_token_valid() {
        let mint = setup();
        let token = mint.issue(500, &[1, 2]).unwrap();

        // Transfer several times
        let mut current = token;
        for _ in 0..5 {
            let result = transfer::transfer(&current).unwrap();
            current = result.token;
        }

        let result = verify_token(&current, &mint.group_public_key(), &mint.pedersen);
        assert!(result.signature_valid);
        assert!(result.value_valid);
        assert!(result.within_bound);
        assert!(result.all_valid());
    }

    #[test]
    fn test_wrong_group_key_fails() {
        let mint = setup();
        let other_mint = setup();
        let token = mint.issue(500, &[1, 2]).unwrap();

        let result = verify_token(&token, &other_mint.group_public_key(), &mint.pedersen);
        assert!(!result.signature_valid);
        assert!(!result.all_valid());
    }

    #[test]
    fn test_tampered_value_fails() {
        let mint = setup();
        let mut token = mint.issue(500, &[1, 2]).unwrap();

        // Tamper with the value
        token.value = 9999;

        let result = verify_token(&token, &mint.group_public_key(), &mint.pedersen);
        assert!(!result.value_valid);
        assert!(!result.all_valid());
    }

    #[test]
    fn test_exceeded_bound_fails() {
        let mint = Mint::setup(MintConfig {
            threshold: 2,
            total_signers: 3,
            recursion_bound: 3,
        });
        let mut token = mint.issue(500, &[1, 2]).unwrap();

        // Manually set transfer count past bound
        token.transfer_count = 4;

        let result = verify_token(&token, &mint.group_public_key(), &mint.pedersen);
        assert!(!result.within_bound);
        assert!(!result.all_valid());
    }

    #[test]
    fn test_many_minted_tokens_all_valid() {
        let mint = setup();
        for i in 0..10 {
            let token = mint.issue(i * 100 + 100, &[1, 3]).unwrap();
            let result = verify_token(&token, &mint.group_public_key(), &mint.pedersen);
            assert!(result.all_valid(), "failed at i={}", i);
        }
    }

    #[test]
    fn test_full_lifecycle_mint_transfer_verify() {
        let mint = setup();
        let token = mint.issue(1000, &[1, 2]).unwrap();

        // Transfer 10 times
        let mut current = token;
        let mut nullifiers = Vec::new();
        let mut nullifier_set = crate::nullifier::NullifierSet::new();

        for i in 0..10 {
            let result = transfer::transfer(&current).unwrap();

            // Check double-spend detection
            assert!(
                transfer::check_double_spend(&mut nullifier_set, &result.spent_nullifier).is_ok(),
                "double-spend false positive at transfer {}",
                i
            );

            nullifiers.push(result.spent_nullifier);
            current = result.token;

            // Verify at each step
            let vr = verify_token(&current, &mint.group_public_key(), &mint.pedersen);
            assert!(vr.all_valid(), "verification failed at transfer {}", i);
        }

        // Final state
        assert_eq!(current.transfer_count, 10);
        assert_eq!(current.value, 1000);
        assert_eq!(nullifier_set.len(), 10);
    }
}
