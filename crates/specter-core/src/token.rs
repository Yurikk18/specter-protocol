//! Proof-Carrying Token (PCT) — the core data structure of Specter.
//!
//! A PCT is a self-verifying bearer token that carries:
//! - A blind signature from the threshold mint (proves legitimate issuance)
//! - A hash chain tracking transfer history (wear-out mechanism)
//! - A nullifier commitment (for double-spend detection)
//! - Value commitment (hides the denomination)
//! - Transfer counter with recursion bound

use curve25519_dalek::{RistrettoPoint, Scalar};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

use specter_blind_sig::types::BlindSignature;

/// A Proof-Carrying Token.
///
/// This is the fundamental unit of value in the Specter protocol.
/// It is a bearer instrument: whoever holds it can spend it.
#[derive(Clone, Debug)]
pub struct ProofCarryingToken {
    /// Unique token identifier (32 bytes, random).
    pub token_id: [u8; 32],

    /// Token value (denomination).
    pub value: u64,

    /// Pedersen commitment to the value: C = value*G + blinding*H.
    pub value_commitment: RistrettoPoint,

    /// Blinding factor for the value commitment (known only to the current owner).
    pub value_blinding: Scalar,

    /// Blind signature from the threshold mint.
    /// Proves this token was legitimately issued.
    pub mint_signature: BlindSignature,

    /// Current owner's secret (32 bytes).
    /// Used to compute the nullifier when spending.
    pub owner_secret: [u8; 32],

    /// Hash chain head — tracks the transfer history.
    /// Each transfer hashes the previous head with the new owner's data.
    pub hash_chain_head: [u8; 32],

    /// Number of times this token has been transferred.
    pub transfer_count: u32,

    /// Maximum number of transfers before the token must be renewed.
    pub recursion_bound: u32,
}

impl ProofCarryingToken {
    /// Check if the token needs to be renewed (transfer count reached bound).
    pub fn needs_renewal(&self) -> bool {
        self.transfer_count >= self.recursion_bound
    }

    /// Get the serialized size estimate in bytes.
    pub fn estimated_size(&self) -> usize {
        32  // token_id
        + 8 // value
        + 32 // value_commitment (compressed)
        + 32 // value_blinding
        + 64 // mint_signature (s + e)
        + 32 // owner_secret
        + 32 // hash_chain_head
        + 4  // transfer_count
        + 4  // recursion_bound
    }

    /// Compute the nullifier for this token (used when spending).
    pub fn compute_nullifier(&self) -> [u8; 32] {
        crate::nullifier::compute_nullifier(&self.owner_secret, &self.token_id)
    }

    /// Compute what was signed by the mint: H(token_id || value_commitment).
    pub fn signed_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.token_id);
        msg.extend_from_slice(self.value_commitment.compress().as_bytes());
        msg
    }
}

/// Advance the hash chain by one step.
///
/// new_head = SHAKE-256("specter-hash-chain:" || old_head || new_owner_data)
pub fn advance_hash_chain(current_head: &[u8; 32], new_data: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"specter-hash-chain:");
    hasher.update(current_head);
    hasher.update(new_data);
    let mut reader = hasher.finalize_xof();
    let mut new_head = [0u8; 32];
    reader.read(&mut new_head);
    new_head
}

#[cfg(test)]
mod tests {
    use super::*;
    use specter_primitives::scalar_utils::{random_scalar, scalar_from_u64};
    use specter_primitives::pedersen::PedersenParams;

    fn dummy_token() -> ProofCarryingToken {
        let params = PedersenParams::new();
        let value = 100u64;
        let blinding = random_scalar();
        let commitment = params.commit(&scalar_from_u64(value), &blinding);

        ProofCarryingToken {
            token_id: [42u8; 32],
            value,
            value_commitment: commitment,
            value_blinding: blinding,
            mint_signature: BlindSignature {
                s: random_scalar(),
                e: random_scalar(),
            },
            owner_secret: [1u8; 32],
            hash_chain_head: [0u8; 32],
            transfer_count: 0,
            recursion_bound: 20,
        }
    }

    #[test]
    fn test_needs_renewal() {
        let mut token = dummy_token();
        assert!(!token.needs_renewal());

        token.transfer_count = 19;
        assert!(!token.needs_renewal());

        token.transfer_count = 20;
        assert!(token.needs_renewal());
    }

    #[test]
    fn test_nullifier_deterministic() {
        let token = dummy_token();
        let n1 = token.compute_nullifier();
        let n2 = token.compute_nullifier();
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_hash_chain_advances() {
        let head = [0u8; 32];
        let new_head = advance_hash_chain(&head, b"transfer-1");
        assert_ne!(head, new_head);

        let newer = advance_hash_chain(&new_head, b"transfer-2");
        assert_ne!(new_head, newer);
        assert_ne!(head, newer);
    }

    #[test]
    fn test_hash_chain_deterministic() {
        let head = [0u8; 32];
        let h1 = advance_hash_chain(&head, b"data");
        let h2 = advance_hash_chain(&head, b"data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_estimated_size() {
        let token = dummy_token();
        let size = token.estimated_size();
        assert!(size > 200); // should be around 240 bytes
    }
}
