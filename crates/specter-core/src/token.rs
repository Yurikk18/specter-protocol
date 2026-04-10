//! Proof-Carrying Token (PCT) - the core data structure of Specter.
//!
//! A PCT is a self-verifying bearer token that carries:
//! - A blind signature from the threshold mint (proves legitimate issuance)
//! - An accumulated proof of transfer history (constant size via folding)
//! - A credential presentation (proves compliance without revealing identity)
//! - A hash chain tracking transfer history (wear-out mechanism)
//! - A nullifier commitment (for double-spend detection)
//! - Value commitment (hides the denomination)

use curve25519_dalek::{RistrettoPoint, Scalar};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use zeroize::Zeroize;

use specter_blind_sig::types::BlindSignature;
use specter_credential::credential::Credential;
use specter_credential::presentation::Presentation;
use specter_fold::accumulator::AccumulatedProof;
use specter_offline::vdf::VdfProof;

/// A Proof-Carrying Token.
///
/// This is the fundamental unit of value in the Specter protocol.
/// It is a bearer instrument: whoever holds it can spend it.
#[derive(Clone)]
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
    pub mint_signature: BlindSignature,

    /// Current owner's secret (32 bytes).
    pub owner_secret: [u8; 32],

    /// Hash chain head - tracks the transfer history.
    pub hash_chain_head: [u8; 32],

    /// Number of times this token has been transferred.
    pub transfer_count: u32,

    /// Maximum number of transfers before the token must be renewed.
    pub recursion_bound: u32,

    /// Accumulated proof of transfer history (constant size).
    pub fold_proof: AccumulatedProof,

    /// Compliance credential (optional - issued by KYC provider).
    pub credential: Option<Credential>,

    /// Current compliance presentation (optional - proves attributes).
    pub presentation: Option<Presentation>,

    /// VDF time-lock proof (proves when the token was issued/renewed).
    pub vdf_proof: Option<VdfProof>,

    /// Bond owner ID (hash of the staker's public key).
    /// If present, the token's offline spending is backed by a bond.
    pub bond_owner_id: Option<[u8; 32]>,
}

impl std::fmt::Debug for ProofCarryingToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofCarryingToken")
            .field("token_id", &hex::encode(self.token_id))
            .field("value", &self.value)
            .field("owner_secret", &"[REDACTED]")
            .field("value_blinding", &"[REDACTED]")
            .field("transfer_count", &self.transfer_count)
            .field("recursion_bound", &self.recursion_bound)
            .field("has_credential", &self.credential.is_some())
            .field("has_vdf", &self.vdf_proof.is_some())
            .field("has_bond", &self.bond_owner_id.is_some())
            .finish()
    }
}

impl ProofCarryingToken {
    /// Check if the token needs to be renewed (transfer count reached bound).
    pub fn needs_renewal(&self) -> bool {
        self.transfer_count >= self.recursion_bound
    }

    /// Get the serialized size estimate in bytes.
    pub fn estimated_size(&self) -> usize {
        let base = 32 + 8 + 32 + 32 + 64 + 32 + 32 + 4 + 4; // basic fields
        let fold = 32 + 32 + 32 + 32 + 4; // AccumulatedProof
        let cred = if self.credential.is_some() { 256 } else { 0 };
        let pres = if self.presentation.is_some() { 512 } else { 0 };
        let vdf = if self.vdf_proof.is_some() { 32 + 8 + 32 } else { 0 }; // seed + iterations + output
        let bond = if self.bond_owner_id.is_some() { 32 } else { 0 };
        base + fold + cred + pres + vdf + bond
    }

    /// Check if the VDF time-lock has expired.
    pub fn is_vdf_expired(&self, required_iterations: u64) -> bool {
        match &self.vdf_proof {
            Some(proof) => specter_offline::vdf::is_expired(proof, required_iterations),
            None => true, // no VDF = always expired for offline use
        }
    }

    /// Check if the token has a bond backing it.
    pub fn has_bond(&self) -> bool {
        self.bond_owner_id.is_some()
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

    /// Check if the token has a compliance credential attached.
    pub fn has_credential(&self) -> bool {
        self.credential.is_some()
    }
}

/// Securely wipe sensitive fields from memory when token is dropped.
impl Drop for ProofCarryingToken {
    fn drop(&mut self) {
        self.owner_secret.zeroize();
        self.value_blinding.zeroize();
    }
}

/// Advance the hash chain by one step.
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

        let genesis = specter_fold::accumulator::TransferState {
            token_id: [42u8; 32],
            owner_hash: [1u8; 32],
            step: 0,
        };
        let fold_proof = specter_fold::accumulator::create_initial_proof(&genesis);

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
            fold_proof,
            credential: None,
            presentation: None,
            vdf_proof: None,
            bond_owner_id: None,
        }
    }

    #[test]
    fn test_needs_renewal() {
        let mut token = dummy_token();
        assert!(!token.needs_renewal());
        token.transfer_count = 20;
        assert!(token.needs_renewal());
    }

    #[test]
    fn test_vdf_expired_when_none() {
        let token = dummy_token();
        assert!(token.is_vdf_expired(100)); // no VDF = expired
    }

    #[test]
    fn test_vdf_not_expired() {
        let mut token = dummy_token();
        let seed = specter_offline::vdf::create_seed(&token.token_id, 1000);
        token.vdf_proof = Some(specter_offline::vdf::evaluate(&seed, 100));
        assert!(!token.is_vdf_expired(100));
        assert!(!token.is_vdf_expired(50));
        assert!(token.is_vdf_expired(200));
    }

    #[test]
    fn test_has_bond() {
        let mut token = dummy_token();
        assert!(!token.has_bond());
        token.bond_owner_id = Some([1u8; 32]);
        assert!(token.has_bond());
    }

    #[test]
    fn test_estimated_size_all_components() {
        let mut token = dummy_token();
        let base = token.estimated_size();

        token.vdf_proof = Some(specter_offline::vdf::evaluate(&[0u8; 32], 10));
        let with_vdf = token.estimated_size();
        assert!(with_vdf > base);

        token.bond_owner_id = Some([1u8; 32]);
        let with_bond = token.estimated_size();
        assert!(with_bond > with_vdf);
    }
}
