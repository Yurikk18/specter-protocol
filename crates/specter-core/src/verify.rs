//! Unified token verification - checks ALL properties of a PCT.

use curve25519_dalek::RistrettoPoint;

use specter_blind_sig::schnorr_blind;
use specter_credential::presentation;
use specter_fold::accumulator;
use specter_primitives::pedersen::PedersenParams;
use specter_primitives::scalar_utils::scalar_from_u64;

use crate::mint;
use crate::token::ProofCarryingToken;

/// Result of token verification - individual checks and combined.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the mint's blind signature is valid.
    pub signature_valid: bool,
    /// Whether the value commitment matches the claimed value.
    pub value_valid: bool,
    /// Whether the transfer count is within the recursion bound.
    pub within_bound: bool,
    /// Whether the accumulated fold proof is valid.
    pub fold_valid: bool,
    /// Whether the compliance credential presentation is valid (None if no credential).
    pub credential_valid: Option<bool>,
    /// Whether the VDF time-lock proof is valid (None if no VDF).
    pub vdf_valid: Option<bool>,
}

impl VerificationResult {
    /// Returns true only if ALL checks passed.
    pub fn all_valid(&self) -> bool {
        self.signature_valid
            && self.value_valid
            && self.within_bound
            && self.fold_valid
            && self.credential_valid.unwrap_or(true)
            && self.vdf_valid.unwrap_or(true)
    }
}

/// Verify a Proof-Carrying Token comprehensively.
///
/// Checks:
/// 1. Blind signature from the mint
/// 2. Value commitment correctness
/// 3. Transfer count within recursion bound
/// 4. Accumulated fold proof validity
/// 5. Compliance credential presentation (if present)
pub fn verify_token(
    token: &ProofCarryingToken,
    group_public_key: &RistrettoPoint,
    pedersen: &PedersenParams,
    credential_pedersen: &PedersenParams,
) -> VerificationResult {
    // 1. Verify mint signature
    let signed_msg = mint::build_signed_message(&token.token_id, &token.value_commitment);
    let signature_valid = schnorr_blind::verify(group_public_key, &signed_msg, &token.mint_signature);

    // 2. Verify value commitment
    let value_scalar = scalar_from_u64(token.value);
    let value_valid = pedersen.verify_opening(
        &token.value_commitment,
        &value_scalar,
        &token.value_blinding,
    );

    // 3. Check transfer count
    let within_bound = token.transfer_count <= token.recursion_bound;

    // 4. Verify fold proof (checks Schnorr equation: s*G == R + e*PK)
    let genesis_state = accumulator::TransferState {
        token_id: token.token_id,
        owner_hash: [0u8; 32],
        step: 0,
    };
    let fold_valid = accumulator::verify_accumulated_proof(&token.fold_proof, &genesis_state);

    // 5. Verify credential presentation (if present)
    let credential_valid = token.presentation.as_ref().map(|pres| {
        presentation::verify_presentation(pres, credential_pedersen)
    });

    // 6. Verify VDF proof (if present)
    let vdf_valid = token.vdf_proof.as_ref().map(|proof| {
        specter_offline::vdf::verify(proof)
    });

    VerificationResult {
        signature_valid,
        value_valid,
        within_bound,
        fold_valid,
        credential_valid,
        vdf_valid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{Mint, MintConfig};
    use crate::transfer;
    use specter_credential::credential::Attributes;

    fn setup() -> Mint {
        Mint::setup(MintConfig {
            threshold: 2,
            total_signers: 3,
            recursion_bound: 20,
        })
    }

    fn test_attrs() -> Attributes {
        Attributes {
            kyc_passed: true,
            not_sanctioned: true,
            jurisdiction: "EU".to_string(),
            age_over_18: true,
            expires_at: 0,
        }
    }

    #[test]
    fn test_fresh_token_valid() {
        let mint = setup();
        let token = mint.issue(500, &[1, 2], Some(&test_attrs())).unwrap();
        let result = verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
        assert!(result.signature_valid);
        assert!(result.value_valid);
        assert!(result.within_bound);
        assert!(result.fold_valid);
        assert_eq!(result.credential_valid, Some(true));
        assert!(result.all_valid());
    }

    #[test]
    fn test_transferred_token_valid() {
        let mint = setup();
        let token = mint.issue(500, &[1, 2], Some(&test_attrs())).unwrap();
        let mut current = token;
        for _ in 0..5 {
            current = transfer::transfer(&current).unwrap().token;
        }
        let result = verify_token(&current, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
        assert!(result.all_valid());
    }

    #[test]
    fn test_no_credential_still_valid() {
        let mint = setup();
        let token = mint.issue(500, &[1, 2], None).unwrap();
        let result = verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
        assert!(result.all_valid());
        assert_eq!(result.credential_valid, None);
    }

    #[test]
    fn test_tampered_value_fails() {
        let mint = setup();
        let mut token = mint.issue(500, &[1, 2], None).unwrap();
        token.value = 9999;
        let result = verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
        assert!(!result.value_valid);
        assert!(!result.all_valid());
    }

    #[test]
    fn test_full_lifecycle() {
        let mint = setup();
        let token = mint.issue(1000, &[1, 2], Some(&test_attrs())).unwrap();
        let mut current = token;
        let mut nullifier_set = crate::nullifier::NullifierSet::new();

        for i in 0..10 {
            let result = transfer::transfer(&current).unwrap();
            assert!(transfer::check_double_spend(&mut nullifier_set, &result.spent_nullifier).is_ok());
            current = result.token;

            let vr = verify_token(&current, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
            assert!(vr.all_valid(), "failed at step {}", i);
            assert_eq!(vr.credential_valid, Some(true));
        }
    }

    #[test]
    fn test_token_with_vdf() {
        let mint = setup();
        let token = mint.issue_full(500, &[1, 2], Some(&test_attrs()), Some(50), None).unwrap();
        let result = verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
        assert!(result.all_valid());
        assert_eq!(result.vdf_valid, Some(true));
    }

    #[test]
    fn test_token_with_bond() {
        let mint = setup();
        let bond_owner = [99u8; 32];
        let token = mint.issue_full(500, &[1, 2], None, None, Some(bond_owner)).unwrap();
        assert!(token.has_bond());
        let result = verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
        assert!(result.all_valid());
    }

    #[test]
    fn test_token_with_all_features() {
        let mint = setup();
        let token = mint.issue_full(500, &[1, 2], Some(&test_attrs()), Some(50), Some([1u8; 32])).unwrap();

        assert!(token.has_credential());
        assert!(token.has_bond());
        assert!(!token.is_vdf_expired(50));

        let result = verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
        assert!(result.all_valid());
        assert_eq!(result.credential_valid, Some(true));
        assert_eq!(result.vdf_valid, Some(true));

        // Transfer preserves all features
        let transferred = crate::transfer::transfer(&token).unwrap().token;
        let vr = verify_token(&transferred, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
        assert!(vr.all_valid());
        assert!(transferred.has_bond());
    }
}
