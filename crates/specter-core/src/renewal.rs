//! Token renewal protocol.
//!
//! When a token reaches its recursion bound (needs_renewal() == true),
//! it must be renewed online. Renewal creates a fresh token with the
//! same value but reset transfer count, new fold proof, and new hash chain.
//! The old token's nullifier is published to prevent reuse.

use specter_blind_sig::threshold::SignerId;

use crate::mint::Mint;
use crate::nullifier::NullifierSet;
use crate::token::ProofCarryingToken;
use crate::verify;

/// Result of a token renewal.
pub struct RenewalResult {
    /// The fresh token (same value, reset transfer count).
    pub new_token: ProofCarryingToken,
    /// Nullifier of the old token (must be published to the network).
    pub old_nullifier: [u8; 32],
}

/// Renew an exhausted token.
///
/// 1. Verifies the old token is valid (signature, value, fold proof)
/// 2. Computes the old token's nullifier (marks it as spent)
/// 3. Issues a fresh token with the same value
/// 4. Returns the new token and the old nullifier for publication
pub fn renew_token(
    old_token: &ProofCarryingToken,
    mint: &Mint,
    signers: &[SignerId],
    nullifier_set: &mut NullifierSet,
) -> Result<RenewalResult, RenewalError> {
    // Verify the old token is still valid (except for the bound check — the
    // whole point of renewal is that the old token is at/past its bound).
    //
    // SECURITY: Skipping fold_valid here previously allowed an attacker to
    // "renew" a tampered/forged token into a fresh one as long as the mint
    // signature survived — i.e. any field the signature doesn't cover (owner
    // secret, fold proof, credential) could be substituted. Enforce all
    // integrity checks before issuing a replacement.
    let vr = verify::verify_token(
        old_token,
        &mint.group_public_key(),
        &mint.pedersen,
        &mint.credential_issuer.pedersen,
        0,
    );

    if !vr.signature_valid {
        return Err(RenewalError::InvalidSignature);
    }
    if !vr.value_valid {
        return Err(RenewalError::InvalidValue);
    }
    if !vr.fold_valid {
        return Err(RenewalError::InvalidFoldProof);
    }
    // If the old token carries a credential presentation, it must still verify.
    // A None credential is fine (matches the fresh-mint path), but if one is
    // attached it must not be forged.
    if matches!(vr.credential_valid, Some(false)) {
        return Err(RenewalError::InvalidCredential);
    }

    // Compute and publish the old nullifier
    let old_nullifier = old_token.compute_nullifier();

    // Check that the old token hasn't already been spent/renewed
    if !nullifier_set.insert(old_nullifier) {
        return Err(RenewalError::AlreadySpent);
    }

    // Issue a fresh token with the same value
    let credential_attrs = old_token
        .credential
        .as_ref()
        .map(|c| &c.attributes);

    let new_token = mint
        .issue(old_token.value, signers, credential_attrs)
        .map_err(|e| RenewalError::MintError(e.to_string()))?;

    Ok(RenewalResult {
        new_token,
        old_nullifier,
    })
}

/// Errors during renewal.
#[derive(Debug, thiserror::Error)]
pub enum RenewalError {
    #[error("old token has invalid signature")]
    InvalidSignature,

    #[error("old token has invalid value commitment")]
    InvalidValue,

    #[error("old token has invalid fold proof")]
    InvalidFoldProof,

    #[error("old token has invalid credential presentation")]
    InvalidCredential,

    #[error("old token has already been spent or renewed")]
    AlreadySpent,

    #[error("mint error: {0}")]
    MintError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::MintConfig;
    use crate::transfer;

    fn setup() -> Mint {
        Mint::setup(MintConfig {
            threshold: 2,
            total_signers: 3,
            recursion_bound: 3, // low bound for testing
        })
    }

    #[test]
    fn test_renew_exhausted_token() {
        let mint = setup();
        let token = mint.issue(1000, &[1, 2], None).unwrap();

        // Exhaust the token
        let mut ns = NullifierSet::new();
        let mut current = token;
        for _ in 0..3 {
            current = transfer::transfer(current, &mut ns).unwrap().token;
        }
        assert!(current.needs_renewal());

        // Renew
        let mut nullifier_set = NullifierSet::new();
        let result = renew_token(&current, &mint, &[1, 2], &mut nullifier_set).unwrap();

        // New token has reset transfer count
        assert_eq!(result.new_token.transfer_count, 0);
        assert_eq!(result.new_token.value, 1000);
        assert!(!result.new_token.needs_renewal());

        // Old nullifier was published
        assert!(nullifier_set.contains(&result.old_nullifier));
    }

    #[test]
    fn test_renewed_token_can_be_transferred() {
        let mint = setup();
        let token = mint.issue(500, &[1, 2], None).unwrap();

        let mut ns = NullifierSet::new();
        let mut current = token;
        for _ in 0..3 {
            current = transfer::transfer(current, &mut ns).unwrap().token;
        }

        let mut renew_ns = NullifierSet::new();
        let result = renew_token(&current, &mint, &[1, 3], &mut renew_ns).unwrap();

        // Can transfer the renewed token
        let mut transfer_ns = NullifierSet::new();
        let transferred = transfer::transfer(result.new_token, &mut transfer_ns).unwrap();
        assert_eq!(transferred.token.transfer_count, 1);
    }

    #[test]
    fn test_double_renewal_rejected() {
        let mint = setup();
        let token = mint.issue(1000, &[1, 2], None).unwrap();

        let mut transfer_ns = NullifierSet::new();
        let mut current = token;
        for _ in 0..3 {
            current = transfer::transfer(current, &mut transfer_ns).unwrap().token;
        }

        let mut ns = NullifierSet::new();
        renew_token(&current, &mint, &[1, 2], &mut ns).unwrap();

        // Second renewal of the same token should fail
        let result = renew_token(&current, &mint, &[1, 2], &mut ns);
        assert!(result.is_err());
    }

    #[test]
    fn test_renewed_token_verifies() {
        let mint = setup();
        let token = mint.issue(1000, &[1, 2], None).unwrap();

        let mut transfer_ns = NullifierSet::new();
        let mut current = token;
        for _ in 0..3 {
            current = transfer::transfer(current, &mut transfer_ns).unwrap().token;
        }

        let mut ns = NullifierSet::new();
        let result = renew_token(&current, &mint, &[1, 2], &mut ns).unwrap();

        let vr = verify::verify_token(
            &result.new_token,
            &mint.group_public_key(),
            &mint.pedersen,
            &mint.credential_issuer.pedersen,
            0,
        );
        assert!(vr.all_valid());
    }
}
