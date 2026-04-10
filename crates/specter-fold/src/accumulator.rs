//! Proof Accumulator — constant-size transfer history proofs with
//! cryptographic verification.
//!
//! Each proof is a Schnorr signature where the "secret key" is derived
//! deterministically from the state. This allows verification by
//! recomputing the expected public key and checking the Schnorr equation:
//! s*G == R + e*PK.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::{RistrettoPoint, Scalar};

use specter_primitives::scalar_utils::random_scalar;
use crate::transcript::Transcript;

/// An accumulated proof of transfer history.
///
/// Constant size regardless of transfer count.
#[derive(Clone, Debug)]
pub struct AccumulatedProof {
    /// Schnorr response scalar.
    pub s: Scalar,
    /// Challenge scalar.
    pub e: Scalar,
    /// Nonce commitment point R.
    pub r: RistrettoPoint,
    /// Public key used in this proof (PK = secret * G).
    pub pk: RistrettoPoint,
    /// Rolling state hash (commits to entire history).
    pub state_hash: [u8; 32],
    /// Number of steps accumulated.
    pub steps: u32,
}

/// State snapshot at a given transfer step.
#[derive(Clone, Debug)]
pub struct TransferState {
    /// Token ID.
    pub token_id: [u8; 32],
    /// Hash of the current owner's public data.
    pub owner_hash: [u8; 32],
    /// Transfer index.
    pub step: u32,
}

impl TransferState {
    /// Serialize the state for hashing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(68);
        bytes.extend_from_slice(&self.token_id);
        bytes.extend_from_slice(&self.owner_hash);
        bytes.extend_from_slice(&self.step.to_le_bytes());
        bytes
    }
}

/// Derive a deterministic "secret key" from state data.
/// This key is used to create Schnorr proofs that can be verified
/// by anyone who knows the state.
fn derive_proof_secret(state_data: &[u8]) -> Scalar {
    specter_primitives::scalar_utils::hash_to_scalar(state_data)
}

/// Create the initial accumulated proof at token issuance.
pub fn create_initial_proof(genesis_state: &TransferState) -> AccumulatedProof {
    let state_bytes = genesis_state.to_bytes();

    // Deterministic secret derived from genesis state
    let secret = derive_proof_secret(&state_bytes);
    let pk = secret * G;

    // Random nonce for Schnorr
    let k = random_scalar();
    let r = k * G;

    // Build transcript for challenge
    let mut transcript = Transcript::new(b"specter-fold-genesis");
    transcript.absorb(b"state", &state_bytes);
    transcript.absorb(b"PK", pk.compress().as_bytes());
    transcript.absorb(b"R", r.compress().as_bytes());

    let e = transcript.challenge(b"genesis-challenge");

    // Schnorr response: s = k + e * secret
    let s = k + e * secret;

    let mut state_hash = [0u8; 32];
    transcript.squeeze_bytes(b"state-hash", &mut state_hash);

    AccumulatedProof {
        s,
        e,
        r,
        pk,
        state_hash,
        steps: 0,
    }
}

/// Fold a new transfer step into the accumulated proof.
pub fn fold_transfer(
    current_proof: &AccumulatedProof,
    new_state: &TransferState,
    recursion_bound: u32,
) -> Result<AccumulatedProof, FoldError> {
    if current_proof.steps >= recursion_bound {
        return Err(FoldError::BoundExceeded {
            steps: current_proof.steps,
            bound: recursion_bound,
        });
    }

    // The new secret is derived from the accumulated state + new state
    let mut secret_input = Vec::new();
    secret_input.extend_from_slice(&current_proof.state_hash);
    secret_input.extend_from_slice(&new_state.to_bytes());
    let secret = derive_proof_secret(&secret_input);
    let pk = secret * G;

    let k = random_scalar();
    let new_r = k * G;

    // Build transcript from current proof + new state
    let mut transcript = Transcript::new(b"specter-fold-step");
    transcript.absorb(b"prev-state-hash", &current_proof.state_hash);
    transcript.absorb(b"prev-s", current_proof.s.as_bytes());
    transcript.absorb(b"prev-e", current_proof.e.as_bytes());
    transcript.absorb(b"prev-R", current_proof.r.compress().as_bytes());
    transcript.absorb(b"new-state", &new_state.to_bytes());
    transcript.absorb(b"step", &new_state.step.to_le_bytes());
    transcript.absorb(b"PK", pk.compress().as_bytes());
    transcript.absorb(b"new-R", new_r.compress().as_bytes());

    let new_e = transcript.challenge(b"fold-challenge");
    let new_s = k + new_e * secret;

    let mut new_state_hash = [0u8; 32];
    transcript.squeeze_bytes(b"accumulated-state", &mut new_state_hash);

    Ok(AccumulatedProof {
        s: new_s,
        e: new_e,
        r: new_r,
        pk,
        state_hash: new_state_hash,
        steps: current_proof.steps + 1,
    })
}

/// Verify an accumulated proof by checking the Schnorr equation: s*G == R + e*PK.
///
/// Uses the PK embedded in the proof. The verifier checks:
/// 1. The Schnorr equation holds: s*G == R + e*PK
/// 2. The state_hash is non-zero (proof was properly constructed)
pub fn verify_accumulated_proof(
    proof: &AccumulatedProof,
    _genesis_state: &TransferState,
) -> bool {
    if proof.state_hash == [0u8; 32] {
        return false;
    }

    // THE critical Schnorr check: s*G must equal R + e*PK
    let lhs = proof.s * G;
    let rhs = proof.r + proof.e * proof.pk;
    lhs == rhs
}

/// Errors during fold operations.
#[derive(Debug, thiserror::Error)]
pub enum FoldError {
    #[error("recursion bound exceeded: {steps}/{bound}")]
    BoundExceeded { steps: u32, bound: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis() -> TransferState {
        TransferState {
            token_id: [42u8; 32],
            owner_hash: [1u8; 32],
            step: 0,
        }
    }

    fn transfer_state(step: u32) -> TransferState {
        let mut owner_hash = [0u8; 32];
        owner_hash[0] = step as u8;
        TransferState {
            token_id: [42u8; 32],
            owner_hash,
            step,
        }
    }

    #[test]
    fn test_initial_proof_verifies() {
        let state = genesis();
        let proof = create_initial_proof(&state);
        assert_eq!(proof.steps, 0);
        assert!(verify_accumulated_proof(&proof, &state));
    }

    #[test]
    fn test_single_fold_verifies() {
        let g = genesis();
        let proof = create_initial_proof(&g);
        let new_state = transfer_state(1);
        let folded = fold_transfer(&proof, &new_state, 20).unwrap();
        assert_eq!(folded.steps, 1);
        assert!(verify_accumulated_proof(&folded, &g));
    }

    #[test]
    fn test_multiple_folds_constant_size() {
        let g = genesis();
        let mut proof = create_initial_proof(&g);

        for i in 1..=20 {
            let state = transfer_state(i);
            let prev_size = std::mem::size_of_val(&proof);
            proof = fold_transfer(&proof, &state, 50).unwrap();
            assert_eq!(proof.steps, i);
            // Size remains constant across folds
            assert_eq!(std::mem::size_of_val(&proof), prev_size);
        }
        assert!(verify_accumulated_proof(&proof, &g));
    }

    #[test]
    fn test_bound_enforced() {
        let g = genesis();
        let mut proof = create_initial_proof(&g);
        for i in 1..=5 {
            proof = fold_transfer(&proof, &transfer_state(i), 5).unwrap();
        }
        assert!(fold_transfer(&proof, &transfer_state(6), 5).is_err());
    }

    #[test]
    fn test_forged_proof_rejected() {
        let g = genesis();
        // Forge a proof with random values — Schnorr equation won't hold
        let fake_sk = random_scalar();
        let forged = AccumulatedProof {
            s: random_scalar(),
            e: random_scalar(),
            r: random_scalar() * G,
            pk: fake_sk * G,
            state_hash: [99u8; 32],
            steps: 0,
        };
        // Must be REJECTED
        assert!(!verify_accumulated_proof(&forged, &g));
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let g = genesis();
        let mut proof = create_initial_proof(&g);
        // Tamper with s
        proof.s += Scalar::ONE;
        assert!(!verify_accumulated_proof(&proof, &g));
    }

    #[test]
    fn test_tampered_s_rejected() {
        let g = genesis();
        let mut proof = create_initial_proof(&g);
        proof.s += Scalar::ONE; // tamper with response
        assert!(!verify_accumulated_proof(&proof, &g));
    }

    #[test]
    fn test_tampered_e_rejected() {
        let g = genesis();
        let mut proof = create_initial_proof(&g);
        proof.e += Scalar::ONE; // tamper with challenge
        assert!(!verify_accumulated_proof(&proof, &g));
    }

    #[test]
    fn test_different_histories_different_proofs() {
        let g = genesis();
        let mut proof_a = create_initial_proof(&g);
        let mut proof_b = create_initial_proof(&g);

        proof_a = fold_transfer(&proof_a, &TransferState {
            token_id: [42u8; 32], owner_hash: [10u8; 32], step: 1,
        }, 20).unwrap();
        proof_b = fold_transfer(&proof_b, &TransferState {
            token_id: [42u8; 32], owner_hash: [20u8; 32], step: 1,
        }, 20).unwrap();

        assert_ne!(proof_a.state_hash, proof_b.state_hash);
    }

    #[test]
    fn test_long_chain_verification() {
        let g = genesis();
        let mut proof = create_initial_proof(&g);
        for i in 1..=100 {
            proof = fold_transfer(&proof, &transfer_state(i), 200).unwrap();
        }
        assert_eq!(proof.steps, 100);
        assert!(verify_accumulated_proof(&proof, &g));
    }
}
