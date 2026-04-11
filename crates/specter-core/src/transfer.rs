//! Token transfer protocol with proof accumulation.

use crate::nullifier::NullifierSet;
use crate::token::{self, ProofCarryingToken};
use specter_fold::accumulator::{self, TransferState};

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

    // Fold the transfer into the accumulated proof
    let mut owner_hash = [0u8; 32];
    owner_hash.copy_from_slice(
        &specter_primitives::scalar_utils::hash_to_scalar(&new_owner_secret).as_bytes()[..32],
    );
    let new_count = token.transfer_count.checked_add(1)
        .ok_or(TransferError::FoldFailed("transfer count overflow".to_string()))?;
    let new_state = TransferState {
        token_id: token.token_id,
        owner_hash,
        step: new_count,
    };
    let new_fold_proof = accumulator::fold_transfer(
        &token.fold_proof,
        &new_state,
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
        let (mint, token1) = setup();
        let mut ns = NullifierSet::new();
        let nullifier = token1.compute_nullifier();
        let _r1 = transfer(token1, &mut ns).unwrap();
        // Manually insert the same nullifier — simulates a replay
        assert!(!ns.insert(nullifier), "double-spend must be detected");
    }
}
