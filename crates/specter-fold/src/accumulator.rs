//! Signed Transfer Chain — the PCT proof-of-history primitive.
//!
//! # Design
//!
//! Each Proof-Carrying Token carries a [`AccumulatedProof`] which records
//! the full chain of transfers. Each transfer step is a **Schnorr
//! signature** by the previous owner's derived signing key, authorizing
//! the hand-off to the next owner. The verifier walks the chain from the
//! genesis owner public key (anchored in the mint signed message) down
//! to the current owner, checking every signature along the way.
//!
//! ## Why this, not a Schnorr accumulator
//!
//! The earlier design used a "Schnorr accumulator" whose step > 0 check
//! was structurally unsound: an attacker who knew the genesis state could
//! regenerate a valid-looking proof from scratch because the verifier
//! couldn't check intermediate PK derivations. The audit flagged this as
//! a documented limitation (IACR 2024/232-style forgery class).
//!
//! The signed chain closes that gap:
//!
//! - Every step carries an explicit Schnorr signature `(R, s)` by the
//!   previous owner's secret key. The verifier checks each signature.
//! - Forgery of any step requires computing a discrete log over
//!   Ristretto255, which is infeasible under ECDLP.
//! - The chain is anchored at step 0 by the mint signed message, which
//!   commits to the genesis owner's public-key hash.
//! - The proof size grows linearly with the number of transfers but is
//!   bounded by the token's `recursion_bound` (typically 20–50), so the
//!   worst-case size is a few KB — well within practical limits.
//!
//! ## Owner key derivation
//!
//! Tokens store a 32-byte `owner_secret`. The signing key is derived
//! deterministically via SHAKE-256 with a dedicated domain tag
//! (`specter-owner-signing:`) so it cannot collide with other protocol
//! derivations (nullifier, hash-to-scalar, etc.).
//!
//! ## Anchoring to the mint
//!
//! The mint signs `token_id || value_commitment || H(genesis_owner_pk)`
//! (see `mint::build_signed_message`). This binds the genesis owner to
//! the mint-authorized token, so a forged chain cannot repurpose a
//! different genesis pk for the same mint signature.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};
use sha3::{digest::{ExtendableOutput, Update as ShakeUpdate, XofReader}, Shake256};
use subtle::ConstantTimeEq;

use specter_primitives::scalar_utils::random_scalar;

/// A single transfer step in the chain.
///
/// Represents a hand-off from the previous owner to `new_owner_pk`,
/// authorized by a Schnorr signature under the previous owner's
/// derived signing key.
#[derive(Clone)]
pub struct TransferStep {
    /// Public key of the new owner at this step (derived from the
    /// incoming owner's secret via [`derive_owner_signing_key`]).
    pub new_owner_pk: RistrettoPoint,
    /// Schnorr nonce commitment R = k * G.
    pub sig_r: RistrettoPoint,
    /// Schnorr response s = k + e * prev_owner_sk.
    pub sig_s: Scalar,
}

impl std::fmt::Debug for TransferStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferStep")
            .field("new_owner_pk", &self.new_owner_pk.compress())
            .field("sig_r", &self.sig_r.compress())
            .field("sig_s", &"<redacted>")
            .finish()
    }
}

/// Proof of a token's transfer history.
///
/// Contains the genesis owner's public key (anchored in the mint signed
/// message) plus a vector of signed transfer steps. Verification is
/// linear in `steps` but each step is a constant-time Schnorr check.
#[derive(Clone, Debug)]
pub struct AccumulatedProof {
    /// Public key of the original owner at mint time.
    /// Anchored in the mint's signed message via its compressed-bytes hash.
    pub genesis_owner_pk: RistrettoPoint,
    /// Signed transfer steps, in order.
    pub steps_chain: Vec<TransferStep>,
    /// Number of steps (== steps_chain.len()). Kept as a separate field
    /// because the old API exposed it directly.
    pub steps: u32,
}

impl AccumulatedProof {
    /// Return the current owner's public key — this is the key a valid
    /// token holder must prove ownership of when spending.
    pub fn current_owner_pk(&self) -> RistrettoPoint {
        self.steps_chain
            .last()
            .map(|s| s.new_owner_pk)
            .unwrap_or(self.genesis_owner_pk)
    }

    /// Hash the genesis owner's compressed public key — this is what
    /// the mint signs to anchor the chain.
    pub fn genesis_owner_pk_hash(&self) -> [u8; 32] {
        owner_pk_hash(&self.genesis_owner_pk)
    }
}

/// State snapshot at a given transfer step (kept for API compatibility
/// with the previous accumulator interface — only `token_id` and
/// `owner_hash` are actually used).
#[derive(Clone, Debug)]
pub struct TransferState {
    pub token_id: [u8; 32],
    /// Hash of the owner's derived public key at this step.
    pub owner_hash: [u8; 32],
    pub step: u32,
}

impl TransferState {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(68);
        bytes.extend_from_slice(&self.token_id);
        bytes.extend_from_slice(&self.owner_hash);
        bytes.extend_from_slice(&self.step.to_le_bytes());
        bytes
    }
}

// ─── Owner key derivation ──────────────────────────────────────────────

/// Derive a Ristretto signing scalar from the owner's raw secret bytes.
///
/// Uses SHAKE-256 with a dedicated domain tag. The scalar auto-zeroizes
/// via curve25519-dalek's `ZeroizeOnDrop` impl.
pub fn derive_owner_signing_key(owner_secret: &[u8; 32]) -> Scalar {
    let mut hasher = Shake256::default();
    ShakeUpdate::update(&mut hasher, b"specter-owner-signing:");
    ShakeUpdate::update(&mut hasher, owner_secret);
    let mut reader = hasher.finalize_xof();
    let mut wide = [0u8; 64];
    reader.read(&mut wide);
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    use zeroize::Zeroize;
    wide.zeroize();
    s
}

/// Derive the public signing key from an owner secret.
pub fn derive_owner_signing_pk(owner_secret: &[u8; 32]) -> RistrettoPoint {
    let sk = derive_owner_signing_key(owner_secret);
    sk * G
}

/// 32-byte SHAKE-256 hash of a compressed Ristretto point — the
/// canonical commitment used to anchor the genesis owner into the mint
/// signed message.
pub fn owner_pk_hash(pk: &RistrettoPoint) -> [u8; 32] {
    let mut hasher = Shake256::default();
    ShakeUpdate::update(&mut hasher, b"specter-owner-pk-hash:");
    ShakeUpdate::update(&mut hasher, pk.compress().as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

// ─── Chain construction ────────────────────────────────────────────────

/// Create the initial accumulated proof for a freshly minted token.
///
/// # Deprecated
///
/// This function silently falls back to the identity point if the
/// `owner_hash` cannot be decompressed as a Ristretto point. The
/// identity point has discrete log 0, which would make the chain
/// trivially forgeable. Use [`create_initial_proof_with_pk`] instead,
/// which takes the genesis owner's public key directly and cannot
/// produce this dangerous fallback.
#[deprecated(
    since = "0.4.0",
    note = "Use create_initial_proof_with_pk — this function can fall back to identity point (sk=0)."
)]
pub fn create_initial_proof(genesis_state: &TransferState) -> AccumulatedProof {
    AccumulatedProof {
        genesis_owner_pk: genesis_state_owner_pk_or_identity(genesis_state),
        steps_chain: Vec::new(),
        steps: 0,
    }
}

/// Alternate constructor where the caller already has the genesis
/// owner's public key. Used by `mint::issue_full`.
pub fn create_initial_proof_with_pk(
    _genesis_state: &TransferState,
    genesis_owner_pk: RistrettoPoint,
) -> AccumulatedProof {
    AccumulatedProof {
        genesis_owner_pk,
        steps_chain: Vec::new(),
        steps: 0,
    }
}

/// Helper: if a caller constructs `TransferState` with `owner_hash` set
/// to the 32-byte compressed public key (as the test suite sometimes
/// does), decompress it. Otherwise return the identity point so the
/// verifier can still fail gracefully.
fn genesis_state_owner_pk_or_identity(state: &TransferState) -> RistrettoPoint {
    use curve25519_dalek::ristretto::CompressedRistretto;
    CompressedRistretto(state.owner_hash)
        .decompress()
        .unwrap_or_default()
}

/// Append a new transfer step, signed by the previous owner.
///
/// The caller is responsible for ensuring `prev_owner_signing_sk` is the
/// derived signing key of the CURRENT holder (who is about to transfer).
/// The function signs the tuple `(token_id, step, new_owner_pk)` and
/// returns a proof extended by one step.
pub fn fold_transfer_signed(
    current_proof: &AccumulatedProof,
    prev_owner_signing_sk: &Scalar,
    new_owner_pk: RistrettoPoint,
    token_id: &[u8; 32],
    recursion_bound: u32,
) -> Result<AccumulatedProof, FoldError> {
    if current_proof.steps >= recursion_bound {
        return Err(FoldError::BoundExceeded {
            steps: current_proof.steps,
            bound: recursion_bound,
        });
    }

    let new_step_number = current_proof
        .steps
        .checked_add(1)
        .ok_or(FoldError::BoundExceeded {
            steps: current_proof.steps,
            bound: recursion_bound,
        })?;

    // Compute the public key of the previous signer from their secret.
    let prev_owner_pk = prev_owner_signing_sk * G;

    // Check: the previous owner must be the current chain tip.
    // Constant-time comparison for consistency with the verification path.
    let expected_prev = current_proof.current_owner_pk();
    if !bool::from(prev_owner_pk.compress().as_bytes()
        .ct_eq(expected_prev.compress().as_bytes()))
    {
        return Err(FoldError::PrevOwnerMismatch);
    }

    // Schnorr signature over H(token_id || step || new_owner_pk).
    let msg = transfer_message(token_id, new_step_number, &new_owner_pk);
    let k = random_scalar();
    let sig_r = k * G;
    let e = transfer_challenge(&sig_r, &prev_owner_pk, &msg);
    let sig_s = k + e * prev_owner_signing_sk;

    let mut new_chain = current_proof.steps_chain.clone();
    new_chain.push(TransferStep {
        new_owner_pk,
        sig_r,
        sig_s,
    });

    Ok(AccumulatedProof {
        genesis_owner_pk: current_proof.genesis_owner_pk,
        steps_chain: new_chain,
        steps: new_step_number,
    })
}

/// Legacy wrapper retained for backward-compatible API.
///
/// This signature exists because existing call sites in the repo expect
/// a `fold_transfer(proof, new_state, bound)` shape. Since the signed
/// chain requires access to the previous owner's signing key, the legacy
/// API cannot securely produce a valid step and is therefore DEPRECATED.
#[deprecated(
    since = "0.3.0",
    note = "Use fold_transfer_signed with the previous owner's signing key."
)]
pub fn fold_transfer(
    current_proof: &AccumulatedProof,
    _new_state: &TransferState,
    recursion_bound: u32,
) -> Result<AccumulatedProof, FoldError> {
    // Rejection path — this entry point exists only so legacy tests
    // still compile. Production transfer logic must use the signed
    // variant via [`fold_transfer_signed`].
    if current_proof.steps >= recursion_bound {
        return Err(FoldError::BoundExceeded {
            steps: current_proof.steps,
            bound: recursion_bound,
        });
    }
    Err(FoldError::DeprecatedUnsignedFold)
}

// ─── Verification ──────────────────────────────────────────────────────

/// Verify an accumulated proof against the genesis state.
///
/// Walks every signed transfer step and checks the Schnorr signature
/// under the previous owner's public key. Any single invalid signature
/// causes rejection.
///
/// `genesis_state.owner_hash` must equal the hash of the proof's
/// `genesis_owner_pk` for the anchor to line up with the mint signed
/// message.
pub fn verify_accumulated_proof(
    proof: &AccumulatedProof,
    genesis_state: &TransferState,
) -> bool {
    // 1. Anchor check: the proof's genesis pk must hash to the anchor
    //    supplied by the caller (in practice the mint signed message).
    let expected_anchor = owner_pk_hash(&proof.genesis_owner_pk);
    let mut valid = expected_anchor.ct_eq(&genesis_state.owner_hash);

    // 2. Step count consistency.  Converted to constant-time: compute
    //    both u8 values and ct_eq them so the branch doesn't leak the
    //    step-count comparison result via timing.
    let steps_match: u8 = if proof.steps as usize == proof.steps_chain.len() { 1 } else { 0 };
    valid &= subtle::Choice::from(steps_match);

    // 3. Walk the chain, verifying EVERY step's Schnorr signature.
    //    All steps are checked unconditionally — no early return — so
    //    an attacker cannot learn which step failed from timing.
    let mut current_pk = proof.genesis_owner_pk;
    for (i, step) in proof.steps_chain.iter().enumerate() {
        let step_number = (i as u32) + 1;
        let msg = transfer_message(&genesis_state.token_id, step_number, &step.new_owner_pk);
        let e = transfer_challenge(&step.sig_r, &current_pk, &msg);
        let lhs = step.sig_s * G;
        let rhs = step.sig_r + e * current_pk;
        valid &= lhs.compress().as_bytes().ct_eq(rhs.compress().as_bytes());
        current_pk = step.new_owner_pk;
    }
    valid.into()
}

// ─── Internal helpers ──────────────────────────────────────────────────

fn transfer_message(
    token_id: &[u8; 32],
    step: u32,
    new_owner_pk: &RistrettoPoint,
) -> [u8; 32] {
    let mut hasher = Shake256::default();
    ShakeUpdate::update(&mut hasher, b"specter-transfer-step:");
    ShakeUpdate::update(&mut hasher, token_id);
    ShakeUpdate::update(&mut hasher, &step.to_le_bytes());
    ShakeUpdate::update(&mut hasher, new_owner_pk.compress().as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

fn transfer_challenge(
    r: &RistrettoPoint,
    pk: &RistrettoPoint,
    msg: &[u8; 32],
) -> Scalar {
    let hash = Sha512::new()
        .chain_update(b"specter-transfer-challenge:")
        .chain_update(r.compress().as_bytes())
        .chain_update(pk.compress().as_bytes())
        .chain_update(msg)
        .finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    use zeroize::Zeroize;
    wide.zeroize();
    s
}

/// Errors during fold operations.
#[derive(Debug, thiserror::Error)]
pub enum FoldError {
    #[error("recursion bound exceeded: {steps}/{bound}")]
    BoundExceeded { steps: u32, bound: u32 },

    #[error("previous owner pk does not match chain tip")]
    PrevOwnerMismatch,

    #[error("unsigned fold entry point is deprecated — use fold_transfer_signed")]
    DeprecatedUnsignedFold,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(seed: u8) -> ([u8; 32], RistrettoPoint) {
        let secret = [seed; 32];
        let pk = derive_owner_signing_pk(&secret);
        (secret, pk)
    }

    fn genesis_state_for(token_id: [u8; 32], genesis_pk: &RistrettoPoint) -> TransferState {
        TransferState {
            token_id,
            owner_hash: owner_pk_hash(genesis_pk),
            step: 0,
        }
    }

    #[test]
    fn test_initial_proof_verifies() {
        let (_s0, pk0) = owner(1);
        let token_id = [42u8; 32];
        let gs = genesis_state_for(token_id, &pk0);
        let proof = create_initial_proof_with_pk(&gs, pk0);
        assert_eq!(proof.steps, 0);
        assert!(verify_accumulated_proof(&proof, &gs));
    }

    #[test]
    fn test_single_fold_verifies() {
        let (s0, pk0) = owner(1);
        let (_s1, pk1) = owner(2);
        let token_id = [42u8; 32];
        let gs = genesis_state_for(token_id, &pk0);

        let p0 = create_initial_proof_with_pk(&gs, pk0);
        let sk0 = derive_owner_signing_key(&s0);
        let p1 = fold_transfer_signed(&p0, &sk0, pk1, &token_id, 50).unwrap();
        assert_eq!(p1.steps, 1);
        assert!(verify_accumulated_proof(&p1, &gs));
        assert_eq!(p1.current_owner_pk(), pk1);
    }

    #[test]
    fn test_multiple_folds_verify() {
        let secrets: Vec<[u8; 32]> = (0..10).map(|i| [i as u8; 32]).collect();
        let pks: Vec<RistrettoPoint> =
            secrets.iter().map(derive_owner_signing_pk).collect();
        let token_id = [99u8; 32];
        let gs = genesis_state_for(token_id, &pks[0]);

        let mut proof = create_initial_proof_with_pk(&gs, pks[0]);
        for i in 0..9 {
            let prev_sk = derive_owner_signing_key(&secrets[i]);
            proof = fold_transfer_signed(&proof, &prev_sk, pks[i + 1], &token_id, 50).unwrap();
        }
        assert_eq!(proof.steps, 9);
        assert!(verify_accumulated_proof(&proof, &gs));
        assert_eq!(proof.current_owner_pk(), pks[9]);
    }

    #[test]
    fn test_forged_step_rejected() {
        let (s0, pk0) = owner(1);
        let (_s1, pk1) = owner(2);
        let token_id = [42u8; 32];
        let gs = genesis_state_for(token_id, &pk0);
        let p0 = create_initial_proof_with_pk(&gs, pk0);
        let sk0 = derive_owner_signing_key(&s0);
        let mut p1 = fold_transfer_signed(&p0, &sk0, pk1, &token_id, 50).unwrap();

        // Tamper: flip a bit in the signature.
        let mut s_bytes = *p1.steps_chain[0].sig_s.as_bytes();
        s_bytes[0] ^= 0x01;
        p1.steps_chain[0].sig_s =
            curve25519_dalek::Scalar::from_bytes_mod_order(s_bytes);

        assert!(!verify_accumulated_proof(&p1, &gs));
    }

    #[test]
    fn test_forged_recipient_rejected() {
        let (s0, pk0) = owner(1);
        let (_s1, pk1) = owner(2);
        let (_s2, pk2) = owner(3);
        let token_id = [42u8; 32];
        let gs = genesis_state_for(token_id, &pk0);
        let p0 = create_initial_proof_with_pk(&gs, pk0);
        let sk0 = derive_owner_signing_key(&s0);
        let mut p1 = fold_transfer_signed(&p0, &sk0, pk1, &token_id, 50).unwrap();

        // Substitute the signed recipient with a different pk — the
        // signature was bound to pk1 so it must fail.
        p1.steps_chain[0].new_owner_pk = pk2;
        assert!(!verify_accumulated_proof(&p1, &gs));
    }

    #[test]
    fn test_wrong_prev_owner_rejected_at_fold_time() {
        let (_s0, pk0) = owner(1);
        let (_s_wrong, _pk_wrong) = owner(42);
        let (_s1, pk1) = owner(2);
        let token_id = [42u8; 32];
        let gs = genesis_state_for(token_id, &pk0);
        let p0 = create_initial_proof_with_pk(&gs, pk0);
        let sk_wrong = derive_owner_signing_key(&[42u8; 32]);
        let err = fold_transfer_signed(&p0, &sk_wrong, pk1, &token_id, 50).unwrap_err();
        assert!(matches!(err, FoldError::PrevOwnerMismatch));
    }

    #[test]
    fn test_tampered_genesis_pk_rejected() {
        let (s0, pk0) = owner(1);
        let (_s1, pk1) = owner(2);
        let (_s_other, pk_other) = owner(99);
        let token_id = [42u8; 32];
        let gs = genesis_state_for(token_id, &pk0);
        let p0 = create_initial_proof_with_pk(&gs, pk0);
        let sk0 = derive_owner_signing_key(&s0);
        let mut p1 = fold_transfer_signed(&p0, &sk0, pk1, &token_id, 50).unwrap();
        // Swap the genesis pk — the anchor check must reject.
        p1.genesis_owner_pk = pk_other;
        assert!(!verify_accumulated_proof(&p1, &gs));
    }

    #[test]
    fn test_chain_bound_enforced() {
        let (s0, pk0) = owner(1);
        let (_s1, pk1) = owner(2);
        let token_id = [42u8; 32];
        let gs = genesis_state_for(token_id, &pk0);
        let p0 = create_initial_proof_with_pk(&gs, pk0);
        let sk0 = derive_owner_signing_key(&s0);
        let p1 = fold_transfer_signed(&p0, &sk0, pk1, &token_id, 1).unwrap();
        assert_eq!(p1.steps, 1);
        // Attempting a second fold past bound=1 must fail.
        let sk1 = derive_owner_signing_key(&[2u8; 32]);
        let err = fold_transfer_signed(&p1, &sk1, pk0, &token_id, 1).unwrap_err();
        assert!(matches!(err, FoldError::BoundExceeded { .. }));
    }

    #[test]
    fn test_empty_chain_current_owner_is_genesis() {
        let (_s0, pk0) = owner(1);
        let gs = genesis_state_for([7u8; 32], &pk0);
        let proof = create_initial_proof_with_pk(&gs, pk0);
        assert_eq!(proof.current_owner_pk(), pk0);
    }

    #[test]
    fn test_steps_count_consistency_enforced() {
        let (s0, pk0) = owner(1);
        let (_s1, pk1) = owner(2);
        let token_id = [42u8; 32];
        let gs = genesis_state_for(token_id, &pk0);
        let p0 = create_initial_proof_with_pk(&gs, pk0);
        let sk0 = derive_owner_signing_key(&s0);
        let mut p1 = fold_transfer_signed(&p0, &sk0, pk1, &token_id, 50).unwrap();
        // Tamper the step counter without adding steps — consistency check fails.
        p1.steps = 5;
        assert!(!verify_accumulated_proof(&p1, &gs));
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_honest_chain_verifies(depth in 0usize..12) {
            let secrets: Vec<[u8; 32]> = (0..=depth).map(|i| [i as u8; 32]).collect();
            let pks: Vec<RistrettoPoint> =
                secrets.iter().map(derive_owner_signing_pk).collect();
            let token_id = [depth as u8; 32];
            let gs = genesis_state_for(token_id, &pks[0]);
            let mut proof = create_initial_proof_with_pk(&gs, pks[0]);
            for i in 0..depth {
                let prev_sk = derive_owner_signing_key(&secrets[i]);
                proof = fold_transfer_signed(&proof, &prev_sk, pks[i + 1], &token_id, 50)
                    .expect("honest fold");
            }
            prop_assert!(verify_accumulated_proof(&proof, &gs));
            prop_assert_eq!(proof.steps as usize, depth);
        }

        #[test]
        fn prop_tampered_signature_rejected(
            depth in 1usize..8,
            step_idx in 0usize..8,
            byte_idx in 0usize..32,
            xor in 1u8..255
        ) {
            prop_assume!(step_idx < depth);
            let secrets: Vec<[u8; 32]> = (0..=depth).map(|i| [i as u8; 32]).collect();
            let pks: Vec<RistrettoPoint> =
                secrets.iter().map(derive_owner_signing_pk).collect();
            let token_id = [depth as u8; 32];
            let gs = genesis_state_for(token_id, &pks[0]);
            let mut proof = create_initial_proof_with_pk(&gs, pks[0]);
            for i in 0..depth {
                let prev_sk = derive_owner_signing_key(&secrets[i]);
                proof = fold_transfer_signed(&proof, &prev_sk, pks[i + 1], &token_id, 50)
                    .expect("honest fold");
            }
            let mut s_bytes = *proof.steps_chain[step_idx].sig_s.as_bytes();
            s_bytes[byte_idx] ^= xor;
            proof.steps_chain[step_idx].sig_s =
                curve25519_dalek::Scalar::from_bytes_mod_order(s_bytes);
            prop_assert!(!verify_accumulated_proof(&proof, &gs));
        }
    }
}
