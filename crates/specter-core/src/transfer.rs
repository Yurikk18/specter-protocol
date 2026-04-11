//! Token transfer protocol with proof accumulation.

use crate::nullifier::NullifierSet;
use crate::token::{self, ProofCarryingToken};
use specter_fold::accumulator;
use specter_primitives::pedersen::PedersenParams;

/// Result of a transfer operation.
pub struct TransferResult {
    /// The updated token (now owned by the recipient).
    pub token: ProofCarryingToken,
    /// The nullifier that should be published to the network.
    pub spent_nullifier: [u8; 32],
}

/// Transfer a token to a new owner.
///
/// Takes ownership of the token (move semantics) to prevent reuse.
/// Atomically inserts the nullifier into the set to prevent double-spend.
/// Returns the new token and the spent nullifier.
pub fn transfer(
    token: ProofCarryingToken,
    nullifier_set: &mut crate::nullifier::NullifierSet,
) -> Result<TransferResult, TransferError> {
    if token.value == 0 {
        return Err(TransferError::InvalidTokenValue);
    }

    if token.needs_renewal() {
        return Err(TransferError::NeedsRenewal {
            transfer_count: token.transfer_count,
            bound: token.recursion_bound,
        });
    }

    // Atomically check and insert nullifier — prevents double-spend
    let spent_nullifier = token.compute_nullifier();
    if !nullifier_set.insert(spent_nullifier) {
        return Err(TransferError::DoubleSpend {
            nullifier: spent_nullifier,
        });
    }

    // Generate new owner secret
    let mut new_owner_secret = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut new_owner_secret);

    // Advance hash chain
    let new_hash_chain = token::advance_hash_chain(&token.hash_chain_head, &new_owner_secret);

    // Derive the new owner's public signing key from their fresh secret,
    // and the CURRENT owner's signing key from the token's owner_secret
    // — the latter is used to sign the transfer step under the signed
    // chain protocol.
    let new_owner_pk = accumulator::derive_owner_signing_pk(&new_owner_secret);
    let prev_owner_sk = accumulator::derive_owner_signing_key(&token.owner_secret);

    let new_count = token.transfer_count.checked_add(1)
        .ok_or(TransferError::FoldFailed("transfer count overflow".to_string()))?;

    // Append a signed step to the chain. fold_transfer_signed cross-
    // checks that prev_owner_sk matches the current chain tip, so a
    // cloned token whose owner_secret was swapped will fail here.
    let new_fold_proof = accumulator::fold_transfer_signed(
        &token.fold_proof,
        &prev_owner_sk,
        new_owner_pk,
        &token.token_id,
        token.recursion_bound,
    )
    .map_err(|e| TransferError::FoldFailed(e.to_string()))?;

    let new_token = ProofCarryingToken {
        token_id: token.token_id,
        value: token.value,
        value_commitment: token.value_commitment,
        value_proof: token.value_proof.clone(),
        mint_signature: token.mint_signature.clone(),
        owner_secret: new_owner_secret,
        hash_chain_head: new_hash_chain,
        transfer_count: new_count,
        recursion_bound: token.recursion_bound,
        fold_proof: new_fold_proof,
        genesis_owner_hash: token.genesis_owner_hash,
        credential: token.credential.clone(),
        presentation: token.presentation.clone(),
        vdf_proof: token.vdf_proof.clone(),
        bond_owner_id: token.bond_owner_id,
    };

    Ok(TransferResult {
        token: new_token,
        spent_nullifier,
    })
}

/// Safer variant of [`transfer`] that re-verifies the input token before
/// inserting its nullifier.
///
/// This is the recommended entry point for any callsite that receives a
/// token from outside its trust boundary (a network peer, a file on disk,
/// a QR code). It performs a full `verify_token` pass — signature, value
/// commitment, recursion bound, fold proof (including the PASS 2
/// current_owner_hash binding), credential presentation, and VDF — and
/// aborts on any failure BEFORE the nullifier is inserted. Without this
/// the caller could burn a nullifier for a tampered token.
pub fn transfer_checked(
    token: ProofCarryingToken,
    nullifier_set: &mut crate::nullifier::NullifierSet,
    group_public_key: &curve25519_dalek::RistrettoPoint,
    pedersen: &PedersenParams,
    credential_pedersen: &PedersenParams,
    current_time: u64,
) -> Result<TransferResult, TransferError> {
    // Full pre-spend verification.
    let vr = crate::verify::verify_token(
        &token,
        group_public_key,
        pedersen,
        credential_pedersen,
        current_time,
    );
    if !vr.signature_valid {
        return Err(TransferError::VerificationFailed("mint signature invalid".into()));
    }
    if !vr.value_valid {
        return Err(TransferError::VerificationFailed(
            "value commitment proof invalid".into(),
        ));
    }
    if !vr.within_bound {
        return Err(TransferError::VerificationFailed(
            "transfer count exceeds recursion bound".into(),
        ));
    }
    if !vr.fold_valid {
        return Err(TransferError::VerificationFailed(
            "fold proof invalid (tampered owner_secret or forged accumulator)".into(),
        ));
    }
    if matches!(vr.credential_valid, Some(false)) {
        return Err(TransferError::VerificationFailed(
            "credential presentation invalid".into(),
        ));
    }
    if matches!(vr.vdf_valid, Some(false)) {
        return Err(TransferError::VerificationFailed(
            "VDF time-lock proof invalid".into(),
        ));
    }

    transfer(token, nullifier_set)
}

/// Check a nullifier against the spent set to detect double-spending.
/// NOTE: When using the new transfer() API, nullifier checking is automatic.
/// This function is retained for external nullifier verification (e.g., network sync).
pub fn check_double_spend(
    nullifier_set: &mut NullifierSet,
    nullifier: &[u8; 32],
) -> Result<(), TransferError> {
    if !nullifier_set.insert(*nullifier) {
        return Err(TransferError::DoubleSpend {
            nullifier: *nullifier,
        });
    }
    Ok(())
}

/// Errors during transfer.
#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("token needs renewal: {transfer_count}/{bound} transfers used")]
    NeedsRenewal { transfer_count: u32, bound: u32 },

    #[error("double-spend detected for nullifier {nullifier:?}")]
    DoubleSpend { nullifier: [u8; 32] },

    #[error("invalid token value: must be > 0")]
    InvalidTokenValue,

    #[error("fold failed: {0}")]
    FoldFailed(String),

    #[error("pre-spend verification failed: {0}")]
    VerificationFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{Mint, MintConfig};

    fn setup() -> (Mint, ProofCarryingToken) {
        let mint = Mint::setup(MintConfig {
            threshold: 2,
            total_signers: 3,
            recursion_bound: 5,
        });
        let token = mint.issue(1000, &[1, 2], None).unwrap();
        (mint, token)
    }

    #[test]
    fn test_transfer_updates_fold_proof() {
        let (_, token) = setup();
        let mut ns = NullifierSet::new();
        let result = transfer(token, &mut ns).unwrap();
        assert_eq!(result.token.fold_proof.steps, 1);
    }

    #[test]
    fn test_transfer_chain_with_fold() {
        let (_, token) = setup();
        let mut ns = NullifierSet::new();
        let mut current = token;
        for i in 0..5 {
            let result = transfer(current, &mut ns).unwrap();
            assert_eq!(result.token.fold_proof.steps, i + 1);
            current = result.token;
        }
        assert!(transfer(current, &mut ns).is_err()); // bound reached
    }

    #[test]
    fn test_double_spend_detected() {
        // Issue two tokens with the same owner_secret to simulate a copy attempt.
        // The second spend of the same nullifier is atomically rejected.
        let (_mint, token1) = setup();
        let mut ns = NullifierSet::new();
        let nullifier = token1.compute_nullifier();
        let _r1 = transfer(token1, &mut ns).unwrap();
        // Manually insert the same nullifier — simulates a replay
        assert!(!ns.insert(nullifier), "double-spend must be detected");
    }

    /// Regression test for transfer_checked blocking the clone attack.
    /// Shows that the safer API catches a tampered token that plain
    /// transfer() would happily accept.
    #[test]
    fn test_transfer_checked_blocks_clone() {
        let (mint, token) = setup();
        // Step 1: advance past genesis so the attack vector applies.
        let mut ns = NullifierSet::new();
        let transferred = transfer(token, &mut ns).unwrap().token;

        // Serialize → tamper owner_secret → deserialize
        let mut bytes = crate::serde_token::serialize_token(&transferred);
        const OWNER_SECRET_OFFSET: usize = 4 + 1 + 32 + 8 + 32 + 32 + 32 + 32 + 32;
        bytes[OWNER_SECRET_OFFSET] ^= 0xFF;
        let cloned = crate::serde_token::deserialize_token(&bytes).unwrap();

        // transfer_checked must reject the tampered token.
        let mut ns2 = NullifierSet::new();
        let result = transfer_checked(
            cloned,
            &mut ns2,
            &mint.group_public_key(),
            &mint.pedersen,
            &mint.credential_issuer.pedersen,
            0,
        );
        assert!(
            matches!(result, Err(TransferError::VerificationFailed(_))),
            "transfer_checked must reject cloned token with swapped owner_secret"
        );
        assert_eq!(
            ns2.len(),
            0,
            "nullifier must NOT be inserted when verification fails"
        );
    }

    /// Regression test for the PASS 2 clone-by-owner-swap attack.
    ///
    /// At step > 0, an attacker could serialize a legitimate token, modify
    /// the `owner_secret` bytes, and deserialize to get a token with a
    /// different nullifier but the same mint signature — enabling an
    /// unbounded cloning attack.
    ///
    /// With the current_owner_hash binding enforced in verify_token, the
    /// cloned token fails verification.
    #[test]
    fn test_clone_by_owner_secret_swap_rejected() {
        let (mint, token) = setup();
        // Transfer once to reach step 1 (the attack requires step > 0 since
        // step = 0 always bound the owner_secret via the genesis derivation).
        let mut ns = NullifierSet::new();
        let transferred = transfer(token, &mut ns).unwrap().token;
        assert_eq!(transferred.fold_proof.steps, 1);

        // Serialize and clone by swapping owner_secret.
        let mut bytes = crate::serde_token::serialize_token(&transferred);
        const OWNER_SECRET_OFFSET: usize = 4 + 1 + 32 + 8 + 32 + 32 + 32 + 32 + 32;
        for b in &mut bytes[OWNER_SECRET_OFFSET..OWNER_SECRET_OFFSET + 32] {
            *b ^= 0xFF;
        }
        let cloned = crate::serde_token::deserialize_token(&bytes).unwrap();
        // The cloned token has a different nullifier — the bare nullifier set
        // would not catch the double-spend.
        assert_ne!(transferred.compute_nullifier(), cloned.compute_nullifier());

        // But verify_token rejects it because current_owner_hash no longer
        // matches H(cloned.owner_secret).
        let vr = crate::verify::verify_token(
            &cloned,
            &mint.group_public_key(),
            &mint.pedersen,
            &mint.credential_issuer.pedersen,
            0,
        );
        assert!(
            !vr.fold_valid,
            "cloned token with swapped owner_secret must fail owner-binding check"
        );
        assert!(
            !vr.all_valid(),
            "cloned token must be rejected by full verification"
        );
    }
}
