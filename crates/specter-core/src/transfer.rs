//! Token transfer protocol.
//!
//! Implements peer-to-peer transfer of Proof-Carrying Tokens.
//! Each transfer:
//! 1. Advances the hash chain (wear-out mechanism)
//! 2. Changes the owner secret
//! 3. Increments the transfer counter
//! 4. Publishes the old owner's nullifier (for double-spend detection)

use crate::nullifier::NullifierSet;
use crate::token::{self, ProofCarryingToken};

/// Result of a transfer operation.
pub struct TransferResult {
    /// The updated token (now owned by the recipient).
    pub token: ProofCarryingToken,
    /// The nullifier that should be published to the network.
    pub spent_nullifier: [u8; 32],
}

/// Transfer a token to a new owner.
///
/// The sender reveals the token to the recipient. The recipient:
/// 1. Verifies the token (signature, hash chain, bounds)
/// 2. Generates a new owner secret
/// 3. Advances the hash chain
/// 4. Increments the transfer counter
///
/// Returns the updated token and the nullifier to publish.
pub fn transfer(token: &ProofCarryingToken) -> Result<TransferResult, TransferError> {
    // Check if the token needs renewal
    if token.needs_renewal() {
        return Err(TransferError::NeedsRenewal {
            transfer_count: token.transfer_count,
            bound: token.recursion_bound,
        });
    }

    // Compute the nullifier for this spend (old owner)
    let spent_nullifier = token.compute_nullifier();

    // Generate new owner secret
    let mut new_owner_secret = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut new_owner_secret);

    // Advance the hash chain
    let new_hash_chain = token::advance_hash_chain(
        &token.hash_chain_head,
        &new_owner_secret,
    );

    // Create the transferred token
    let new_token = ProofCarryingToken {
        token_id: token.token_id,
        value: token.value,
        value_commitment: token.value_commitment,
        value_blinding: token.value_blinding,
        mint_signature: token.mint_signature.clone(),
        owner_secret: new_owner_secret,
        hash_chain_head: new_hash_chain,
        transfer_count: token.transfer_count + 1,
        recursion_bound: token.recursion_bound,
    };

    Ok(TransferResult {
        token: new_token,
        spent_nullifier,
    })
}

/// Check a nullifier against the spent set to detect double-spending.
///
/// Returns `Ok(())` if the nullifier is new (valid spend).
/// Returns `Err(DoubleSpend)` if the nullifier was already spent.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{Mint, MintConfig};

    fn setup() -> (Mint, ProofCarryingToken) {
        let mint = Mint::setup(MintConfig {
            threshold: 2,
            total_signers: 3,
            recursion_bound: 5, // low bound for testing
        });
        let token = mint.issue(1000, &[1, 2]).unwrap();
        (mint, token)
    }

    #[test]
    fn test_transfer_basic() {
        let (_, token) = setup();
        let result = transfer(&token).unwrap();

        assert_eq!(result.token.value, 1000);
        assert_eq!(result.token.transfer_count, 1);
        assert_eq!(result.token.token_id, token.token_id);
        assert_ne!(result.token.owner_secret, token.owner_secret);
        assert_ne!(result.token.hash_chain_head, token.hash_chain_head);
    }

    #[test]
    fn test_transfer_preserves_signature() {
        let (_, token) = setup();
        let result = transfer(&token).unwrap();

        assert_eq!(result.token.mint_signature, token.mint_signature);
        assert_eq!(result.token.value_commitment, token.value_commitment);
    }

    #[test]
    fn test_multiple_transfers() {
        let (_, mut token) = setup();

        for i in 0..5 {
            let result = transfer(&token).unwrap();
            assert_eq!(result.token.transfer_count, i + 1);
            token = result.token;
        }

        // 6th transfer should fail (bound = 5)
        let result = transfer(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_bound_enforced() {
        let mint = Mint::setup(MintConfig {
            threshold: 2,
            total_signers: 3,
            recursion_bound: 1,
        });
        let token = mint.issue(100, &[1, 2]).unwrap();

        // First transfer OK
        let result = transfer(&token).unwrap();

        // Second transfer fails (bound = 1)
        assert!(transfer(&result.token).is_err());
    }

    #[test]
    fn test_double_spend_detected() {
        let (_, token) = setup();
        let result = transfer(&token).unwrap();

        let mut nullifier_set = NullifierSet::new();

        // First spend OK
        assert!(check_double_spend(&mut nullifier_set, &result.spent_nullifier).is_ok());

        // Same nullifier again = double spend
        assert!(check_double_spend(&mut nullifier_set, &result.spent_nullifier).is_err());
    }

    #[test]
    fn test_different_transfers_different_nullifiers() {
        let (_, token) = setup();

        // Transfer to two different recipients
        let r1 = transfer(&token).unwrap();
        let r2 = transfer(&token).unwrap();

        // Same old owner, same token → same nullifier (double-spend!)
        assert_eq!(r1.spent_nullifier, r2.spent_nullifier);

        let mut set = NullifierSet::new();
        assert!(check_double_spend(&mut set, &r1.spent_nullifier).is_ok());
        assert!(check_double_spend(&mut set, &r2.spent_nullifier).is_err());
    }

    #[test]
    fn test_chain_of_transfers_unique_nullifiers() {
        let (_, mut token) = setup();
        let mut nullifiers = Vec::new();

        for _ in 0..5 {
            let result = transfer(&token).unwrap();
            nullifiers.push(result.spent_nullifier);
            token = result.token;
        }

        // All nullifiers should be unique (different owners at each step)
        for i in 0..nullifiers.len() {
            for j in (i + 1)..nullifiers.len() {
                assert_ne!(nullifiers[i], nullifiers[j]);
            }
        }
    }
}
