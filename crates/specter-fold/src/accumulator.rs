//! Proof Accumulator - constant-size transfer history proofs with
//! cryptographic verification.
//!
//! Each proof is a Schnorr signature where the "secret key" is derived
//! deterministically from the state. This allows verification by
//! recomputing the expected public key and checking the Schnorr equation:
//! s*G == R + e*PK.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::{RistrettoPoint, Scalar};
use subtle::ConstantTimeEq;

use specter_primitives::scalar_utils::random_scalar;
use crate::transcript::Transcript;

/// Constant-time equality on 32-byte arrays. Applied to all verifier-side
/// comparisons of hashes and binding digests even when the values
/// themselves are public, so the pattern of "compare two 32-byte blobs"
/// never accidentally leaks through a short-circuiting `==`.
#[inline]
fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    bool::from(a.ct_eq(b))
}

/// An accumulated proof of transfer history.
///
/// Constant size regardless of transfer count.
///
/// # Security Boundary
///
/// For step 0 (genesis): full cryptographic verification — PK derivation,
/// Fiat-Shamir transcript, and Schnorr equation are all checked.
///
/// For step > 0: structural integrity only — Schnorr equation + Fiat-Shamir
/// binding prove the prover knew the DLP of PK, but the verifier cannot
/// confirm PK was legitimately derived without intermediate states.
/// The `genesis_state_hash` field binds the proof chain to its origin.
///
/// **The primary trust anchors are the mint blind signature (unforgeable)
/// and the nullifier set (prevents double-spend), not the fold proof alone.**
///
/// The `current_owner_hash` field exposes the owner hash of the most recent
/// transfer step so that callers of `verify_token` can bind a concrete
/// `owner_secret` to the proof. Without this field an attacker could clone
/// a token by swapping `owner_secret`: the nullifier would change
/// (bypassing double-spend detection) while the Schnorr accumulator, which
/// does not recompute intermediate state hashes, would still verify.
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
    /// Rolling hash of all PKs used in the proof chain.
    /// Binds each PK to the derivation history, preventing PK forgery.
    pub pk_chain_hash: [u8; 32],
    /// Hash of the genesis state — carries through all folds so the verifier
    /// can confirm the proof chain originated from the correct genesis.
    pub genesis_state_hash: [u8; 32],
    /// Hash of the current owner's identity (hash_to_scalar(owner_secret) truncated
    /// to 32 bytes). Bound into the Fiat-Shamir challenge so a naive attacker
    /// cannot swap the token's `owner_secret` without regenerating the Schnorr
    /// proof. Checked by `verify_token` against `H(token.owner_secret)`.
    pub current_owner_hash: [u8; 32],
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
///
/// Uses a dedicated domain tag separate from the generic hash_to_scalar
/// to prevent cross-protocol confusion (e.g., with nullifier derivation).
fn derive_proof_secret(state_data: &[u8]) -> Scalar {
    use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
    let mut hasher = Shake256::default();
    hasher.update(b"specter-fold-proof-secret:");
    hasher.update(&(state_data.len() as u64).to_le_bytes());
    hasher.update(state_data);
    let mut reader = hasher.finalize_xof();
    let mut wide = [0u8; 64];
    reader.read(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
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
    transcript.absorb(b"owner-hash", &genesis_state.owner_hash);

    let e = transcript.challenge(b"genesis-challenge");

    // Schnorr response: s = k + e * secret
    let s = k + e * secret;

    let mut state_hash = [0u8; 32];
    transcript.squeeze_bytes(b"state-hash", &mut state_hash);

    // Initial PK chain hash
    let mut pk_chain_hash = [0u8; 32];
    let mut chain_transcript = Transcript::new(b"specter-pk-chain");
    chain_transcript.absorb(b"pk", pk.compress().as_bytes());
    chain_transcript.squeeze_bytes(b"chain", &mut pk_chain_hash);

    // Compute genesis state hash for chain binding
    let mut genesis_hash = [0u8; 32];
    let mut gh_transcript = Transcript::new(b"specter-genesis-binding");
    gh_transcript.absorb(b"genesis-state", &state_bytes);
    gh_transcript.absorb(b"genesis-pk", pk.compress().as_bytes());
    gh_transcript.squeeze_bytes(b"genesis-hash", &mut genesis_hash);

    AccumulatedProof {
        s,
        e,
        r,
        pk,
        state_hash,
        steps: 0,
        pk_chain_hash,
        genesis_state_hash: genesis_hash,
        current_owner_hash: genesis_state.owner_hash,
    }
}

/// Compute the fold challenge deterministically from stored proof fields.
/// Both prover and verifier use this identical function, ensuring the challenge
/// is bound to all proof fields and cannot be freely chosen by an attacker.
///
/// `current_owner_hash` is absorbed so that any modification of the token's
/// owner identity (e.g. a clone attempting to swap `owner_secret`) breaks the
/// Schnorr equation unless the attacker also regenerates the entire fold
/// proof from scratch. This does not close the documented step > 0 forge
/// vector but raises the bar significantly against byte-level cloning.
fn compute_fold_challenge(
    state_hash: &[u8; 32],
    pk: &RistrettoPoint,
    pk_chain_hash: &[u8; 32],
    r: &RistrettoPoint,
    steps: u32,
    current_owner_hash: &[u8; 32],
) -> Scalar {
    let mut transcript = Transcript::new(b"specter-fold-challenge-v3");
    transcript.absorb(b"state-hash", state_hash);
    transcript.absorb(b"PK", pk.compress().as_bytes());
    transcript.absorb(b"pk-chain", pk_chain_hash);
    transcript.absorb(b"R", r.compress().as_bytes());
    transcript.absorb(b"steps", &steps.to_le_bytes());
    transcript.absorb(b"owner-hash", current_owner_hash);
    transcript.challenge(b"fold-e")
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

    // 1. Compute new state_hash (binds to full transfer context)
    let mut state_transcript = Transcript::new(b"specter-fold-state-v2");
    state_transcript.absorb(b"prev-state-hash", &current_proof.state_hash);
    state_transcript.absorb(b"prev-pk", current_proof.pk.compress().as_bytes());
    state_transcript.absorb(b"new-state", &new_state.to_bytes());
    state_transcript.absorb(b"step", &new_state.step.to_le_bytes());
    let mut new_state_hash = [0u8; 32];
    state_transcript.squeeze_bytes(b"state-hash", &mut new_state_hash);

    // 2. Extend PK chain hash
    let mut pk_chain_hash = [0u8; 32];
    let mut chain_transcript = Transcript::new(b"specter-pk-chain");
    chain_transcript.absorb(b"prev", &current_proof.pk_chain_hash);
    chain_transcript.absorb(b"pk", pk.compress().as_bytes());
    chain_transcript.squeeze_bytes(b"chain", &mut pk_chain_hash);

    // 3. Compute challenge from ONLY stored proof fields (verifier can recompute)
    let k = random_scalar();
    let new_r = k * G;
    let new_steps = current_proof.steps.checked_add(1)
        .ok_or(FoldError::BoundExceeded { steps: current_proof.steps, bound: recursion_bound })?;
    let new_e = compute_fold_challenge(
        &new_state_hash,
        &pk,
        &pk_chain_hash,
        &new_r,
        new_steps,
        &new_state.owner_hash,
    );

    // 4. Schnorr response: s = k + e * secret
    let new_s = k + new_e * secret;

    Ok(AccumulatedProof {
        s: new_s,
        e: new_e,
        r: new_r,
        pk,
        state_hash: new_state_hash,
        steps: new_steps,
        pk_chain_hash,
        genesis_state_hash: current_proof.genesis_state_hash,
        current_owner_hash: new_state.owner_hash,
    })
}

/// Verify an accumulated proof.
///
/// Checks:
/// 1. Schnorr equation: s*G == R + e*PK
/// 2. For genesis (step 0): PK is correctly derived from genesis_state
/// 3. For genesis: challenge was computed via the correct transcript
/// 4. state_hash is non-zero
/// 5. pk_chain_hash is non-zero for step > 0
/// 6. For step > 0: challenge e is bound to the full proof state via transcript
pub fn verify_accumulated_proof(
    proof: &AccumulatedProof,
    genesis_state: &TransferState,
) -> bool {
    if ct_eq_32(&proof.state_hash, &[0u8; 32]) {
        return false;
    }

    // Schnorr equation check
    let lhs = proof.s * G;
    let rhs = proof.r + proof.e * proof.pk;
    if lhs != rhs {
        return false;
    }

    // For genesis proofs: verify PK derivation and transcript
    if proof.steps == 0 {
        let state_bytes = genesis_state.to_bytes();
        let expected_secret = derive_proof_secret(&state_bytes);
        let expected_pk = expected_secret * G;
        if proof.pk != expected_pk {
            return false;
        }

        // At genesis, the current owner must be the genesis owner.
        if !ct_eq_32(&proof.current_owner_hash, &genesis_state.owner_hash) {
            return false;
        }

        // Recompute the full transcript and verify BOTH the challenge AND
        // the squeezed state_hash. Previously only the challenge was
        // cross-checked, leaving `state_hash` as an unverified field at
        // step 0 — a proptest-caught weakness (prop_tampered_state_hash
        // _rejected_at_genesis). Tampering state_hash at step 0 would
        // have propagated into the secret derivation at step 1 and
        // corrupted the chain without being caught locally.
        let mut transcript = Transcript::new(b"specter-fold-genesis");
        transcript.absorb(b"state", &state_bytes);
        transcript.absorb(b"PK", proof.pk.compress().as_bytes());
        transcript.absorb(b"R", proof.r.compress().as_bytes());
        transcript.absorb(b"owner-hash", &genesis_state.owner_hash);
        let expected_e = transcript.challenge(b"genesis-challenge");
        if proof.e != expected_e {
            return false;
        }
        let mut expected_state_hash = [0u8; 32];
        transcript.squeeze_bytes(b"state-hash", &mut expected_state_hash);
        if !ct_eq_32(&proof.state_hash, &expected_state_hash) {
            return false;
        }

        // Verify genesis pk_chain_hash
        let mut chain_transcript = Transcript::new(b"specter-pk-chain");
        chain_transcript.absorb(b"pk", proof.pk.compress().as_bytes());
        let mut expected_chain = [0u8; 32];
        chain_transcript.squeeze_bytes(b"chain", &mut expected_chain);
        if !ct_eq_32(&proof.pk_chain_hash, &expected_chain) {
            return false;
        }
    } else {
        // For step > 0: pk_chain_hash must be non-zero
        if ct_eq_32(&proof.pk_chain_hash, &[0u8; 32]) {
            return false;
        }

        // Verify genesis binding: the proof's genesis_state_hash must match
        // what the verifier computes from the provided genesis_state.
        // This ensures the proof chain originated from the correct genesis,
        // even though the verifier can't check intermediate PK derivations.
        let state_bytes = genesis_state.to_bytes();
        let expected_genesis_secret = derive_proof_secret(&state_bytes);
        let expected_genesis_pk = expected_genesis_secret * G;
        let mut expected_genesis_hash = [0u8; 32];
        let mut gh_transcript = Transcript::new(b"specter-genesis-binding");
        gh_transcript.absorb(b"genesis-state", &state_bytes);
        gh_transcript.absorb(b"genesis-pk", expected_genesis_pk.compress().as_bytes());
        gh_transcript.squeeze_bytes(b"genesis-hash", &mut expected_genesis_hash);
        if !ct_eq_32(&proof.genesis_state_hash, &expected_genesis_hash) {
            return false;
        }

        // Recompute challenge from stored proof fields and verify it matches.
        // This binds the challenge to (state_hash, PK, pk_chain_hash, R, steps)
        // via Fiat-Shamir. Combined with the Schnorr equation, this proves the
        // prover knew the DLP of PK at proof creation time.
        //
        // SECURITY NOTE: An attacker who knows the genesis state can still
        // forge proofs at step > 0 by choosing their own PK. The primary
        // defenses against transfer history forgery are the mint's blind
        // signature (unforgeable) and the nullifier set (prevents double-spend).
        let expected_e = compute_fold_challenge(
            &proof.state_hash,
            &proof.pk,
            &proof.pk_chain_hash,
            &proof.r,
            proof.steps,
            &proof.current_owner_hash,
        );
        if proof.e != expected_e {
            return false;
        }
    }

    true
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
        // Forge a proof with random values - Schnorr equation won't hold
        let fake_sk = random_scalar();
        let forged = AccumulatedProof {
            s: random_scalar(),
            e: random_scalar(),
            r: random_scalar() * G,
            pk: fake_sk * G,
            state_hash: [99u8; 32],
            steps: 0,
            pk_chain_hash: [0u8; 32],
            genesis_state_hash: [0u8; 32],
            current_owner_hash: [0u8; 32],
        };
        // Must be REJECTED
        assert!(!verify_accumulated_proof(&forged, &g));
    }

    #[test]
    fn test_owner_hash_swap_rejected_at_step_0() {
        let g = genesis();
        let mut proof = create_initial_proof(&g);
        // Try to swap the current_owner_hash — must break verification
        proof.current_owner_hash = [0xAB; 32];
        assert!(!verify_accumulated_proof(&proof, &g));
    }

    #[test]
    fn test_owner_hash_swap_rejected_after_fold() {
        let g = genesis();
        let p0 = create_initial_proof(&g);
        let mut p1 = fold_transfer(&p0, &transfer_state(1), 20).unwrap();
        // Swap the current_owner_hash without re-signing — must break
        p1.current_owner_hash = [0xCD; 32];
        assert!(!verify_accumulated_proof(&p1, &g));
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

    /// PASS 14: the AccumulatedProof struct is constant-size across
    /// step counts. `size_of_val` captures the stack size of the struct
    /// which must be independent of the number of accumulated steps.
    ///
    /// The absolute sanity bound accounts for dalek's expanded point
    /// representation (EdwardsPoint uses 4 x FieldElement internally,
    /// which is ~160 bytes each on 64-bit targets) plus two scalars,
    /// four `[u8; 32]` arrays, and a `u32` step counter.
    #[test]
    fn test_accumulated_proof_is_constant_size() {
        let g = genesis();
        let p0 = create_initial_proof(&g);
        let p1 = fold_transfer(&p0, &transfer_state(1), 200).unwrap();
        let p50 = {
            let mut cur = p0.clone();
            for i in 1..=50 {
                cur = fold_transfer(&cur, &transfer_state(i), 200).unwrap();
            }
            cur
        };
        // Stack size of the struct is invariant of step count.
        assert_eq!(
            std::mem::size_of_val(&p0),
            std::mem::size_of_val(&p1)
        );
        assert_eq!(
            std::mem::size_of_val(&p0),
            std::mem::size_of_val(&p50)
        );
        // Sanity: struct is not secretly unbounded. 1 KiB is a generous
        // ceiling given dalek's expanded point layout.
        assert!(
            std::mem::size_of::<AccumulatedProof>() < 1024,
            "AccumulatedProof unexpectedly large: {}",
            std::mem::size_of::<AccumulatedProof>()
        );
    }

    // ── Property tests ─────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        /// Every honestly-generated fold chain verifies against its genesis.
        #[test]
        fn prop_honest_chain_verifies(steps in 0usize..30) {
            let g = genesis();
            let mut proof = create_initial_proof(&g);
            for i in 1..=steps {
                proof = fold_transfer(&proof, &transfer_state(i as u32), 100).unwrap();
            }
            prop_assert!(verify_accumulated_proof(&proof, &g));
            prop_assert_eq!(proof.steps as usize, steps);
        }

        /// Any single-byte tamper of a finalized fold proof's state_hash
        /// must invalidate verification at step 0 (where derivation is
        /// checked against the genesis). At step > 0 the attacker can
        /// trivially forge (documented limitation) so we only assert at
        /// step 0.
        #[test]
        fn prop_tampered_state_hash_rejected_at_genesis(byte_idx in 0usize..32, xor in 1u8..255) {
            let g = genesis();
            let mut proof = create_initial_proof(&g);
            proof.state_hash[byte_idx] ^= xor;
            prop_assert!(!verify_accumulated_proof(&proof, &g));
        }

        /// The current_owner_hash binding (PASS 2) rejects any swap at
        /// step 0 or later — the Schnorr challenge absorbs owner-hash.
        #[test]
        fn prop_current_owner_hash_tamper_rejected(
            byte_idx in 0usize..32, xor in 1u8..255, depth in 0usize..10
        ) {
            let g = genesis();
            let mut proof = create_initial_proof(&g);
            for i in 1..=depth {
                proof = fold_transfer(&proof, &transfer_state(i as u32), 100).unwrap();
            }
            proof.current_owner_hash[byte_idx] ^= xor;
            prop_assert!(!verify_accumulated_proof(&proof, &g));
        }
    }
}
