//! Bit-decomposition range proof for 64-bit values committed via a
//! Pedersen commitment `C = v*G + r*H`.
//!
//! # Design
//!
//! Proves `v ∈ [0, 2^64)` for a given commitment `C` without revealing
//! `v` or `r`. Used when confidential transactions are enabled (the
//! plaintext `value: u64` field is removed and only the commitment
//! survives).
//!
//! This is an intentionally-simple construction, not Bulletproofs:
//!
//! 1. Decompose `v` into 64 bits `b_0, b_1, ..., b_63`.
//! 2. For each bit `i`, create a "bit commitment" `B_i = b_i*G + s_i*H`
//!    where `s_i` is a per-bit random blinding.
//! 3. Prove each `B_i` opens to EITHER `0*G + s_i*H` OR `1*G + s_i*H`
//!    via a Chaum-Pedersen OR-proof (aka "Schnorr OR-proof").
//! 4. Prove that `sum_i 2^i * B_i == C` in blinding-consistent form,
//!    which forces `sum_i 2^i * b_i == v` and `sum_i 2^i * s_i == r`.
//!
//! The resulting proof is ~8 KB (vs ~576 B for Bulletproofs+) but has
//! zero external dependencies and is straightforward to audit. When
//! Specter switches to confidential transactions for real, upgrade to
//! a Bulletproofs+-backed variant via a new feature flag; until then
//! this primitive is sufficient to prove correctness of the
//! confidential-tx design.
//!
//! # Threat model
//!
//! - **Soundness**: forging a proof for `v ≥ 2^64` requires breaking
//!   the discrete log of `H` with respect to `G`, under the random
//!   oracle assumption on SHA-512.
//! - **Zero-knowledge**: the proof leaks no information about `v` or
//!   `r` beyond what the commitment itself leaks (which is nothing).
//! - **Soundness of the OR-proof**: standard Chaum-Pedersen disjunction
//!   with Fiat-Shamir challenge split. Each bit commitment is proven
//!   to satisfy EXACTLY ONE of the two statements.
//!
//! # Not intended for production confidential transactions
//!
//! 8 KB per range proof is expensive. Specter's current model keeps
//! `value: u64` plaintext precisely to avoid this cost. This module
//! is groundwork — the confidential-tx migration path will eventually
//! switch to Bulletproofs+ via an external crate.
//!
//! # References
//!
//! - Schnorr, "Efficient Identification and Signatures for Smart
//!   Cards", CRYPTO '89
//! - Cramer-Damgård-Schoenmakers, "Proofs of Partial Knowledge and
//!   Simplified Design of Witness Hiding Protocols", CRYPTO '94
//! - Bulletproofs, Bünz et al., 2018 (eventual replacement)

use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};

use crate::pedersen::PedersenParams;
use crate::scalar_utils::random_scalar;

// NOTE: Pedersen commitments in this crate use `params.g` (a NUMS
// point hashed from "specter-pedersen-generator-G"), NOT the Ristretto
// basepoint. The OR-proof must subtract `params.g`, not the basepoint,
// when checking the "bit = 1" statement `B - g = s*h`.

/// Number of bits in the range. Fixed at 64 to match the `u64` value
/// space Specter uses for token denominations.
pub const RANGE_BITS: usize = 64;

/// A Chaum-Pedersen OR-proof that a commitment `C` opens to either
/// `0*G + s*H` or `1*G + s*H`.
///
/// The verifier cannot tell which branch is the "real" one.
#[derive(Clone, Debug)]
pub struct BitOrProof {
    pub a0: RistrettoPoint,
    pub a1: RistrettoPoint,
    pub c0: Scalar,
    pub c1: Scalar,
    pub r0: Scalar,
    pub r1: Scalar,
}

/// A 64-bit range proof.
#[derive(Clone, Debug)]
pub struct RangeProof {
    /// Per-bit commitments `B_i = b_i*G + s_i*H`.
    pub bit_commits: Vec<RistrettoPoint>,
    /// Per-bit OR-proofs that each `B_i` is a commitment to 0 or 1.
    pub bit_proofs: Vec<BitOrProof>,
}

/// Prove that a Pedersen commitment `C = v*G + r*H` commits to a value
/// in `[0, 2^64)`.
///
/// Returns the `RangeProof` that can be verified against the same `C`.
///
/// # Panics
///
/// Never panics. If `v ≥ 2^64` the caller has already violated the
/// u64 type — this function works on bit decomposition so any input
/// is valid, but the verifier will reject values outside range.
pub fn prove_range_64(
    params: &PedersenParams,
    v: u64,
    r: &Scalar,
) -> RangeProof {
    let mut bit_commits = Vec::with_capacity(RANGE_BITS);
    let mut bit_proofs = Vec::with_capacity(RANGE_BITS);
    let mut bit_blindings: Vec<Scalar> = Vec::with_capacity(RANGE_BITS);

    // The last blinding is derived so that sum_i 2^i * s_i = r.
    // We pick the first 63 blindings randomly and force the 64th.
    for _i in 0..(RANGE_BITS - 1) {
        bit_blindings.push(random_scalar());
    }
    // s_{63} = (r - sum_{i=0..62} 2^i * s_i) / 2^63
    let mut accumulated = Scalar::ZERO;
    let mut two_pow_i = Scalar::ONE;
    for s_i in &bit_blindings {
        accumulated += two_pow_i * s_i;
        two_pow_i += two_pow_i; // 2^{i+1}
    }
    // two_pow_i is now 2^63. Solve for s_{63}:
    let two_pow_63 = two_pow_i;
    let s_last = (r - accumulated) * two_pow_63.invert();
    bit_blindings.push(s_last);

    for i in 0..RANGE_BITS {
        let bit = (v >> i) & 1;
        let b_scalar = Scalar::from(bit);
        let b_i = params.commit(&b_scalar, &bit_blindings[i]);
        bit_commits.push(b_i);
        bit_proofs.push(prove_bit_or(params, &b_i, bit, &bit_blindings[i]));
    }

    RangeProof {
        bit_commits,
        bit_proofs,
    }
}

/// Verify a range proof against a Pedersen commitment `C`.
pub fn verify_range_64(
    params: &PedersenParams,
    commitment: &RistrettoPoint,
    proof: &RangeProof,
) -> bool {
    if proof.bit_commits.len() != RANGE_BITS
        || proof.bit_proofs.len() != RANGE_BITS
    {
        return false;
    }

    // 1. Every bit commitment must be a valid commitment to 0 or 1.
    for (i, bit_commit) in proof.bit_commits.iter().enumerate() {
        if !verify_bit_or(params, bit_commit, &proof.bit_proofs[i]) {
            return false;
        }
    }

    // 2. The weighted sum of bit commitments must equal the original
    //    commitment: sum_i 2^i * B_i == C.
    //
    //    If every B_i = b_i*G + s_i*H with b_i in {0,1}, then
    //    sum_i 2^i * B_i = (sum_i 2^i * b_i)*G + (sum_i 2^i * s_i)*H
    //                    = v*G + r*H = C
    //    The equality check forces both the value and the blinding
    //    sums to agree, which ties the bits to the committed value.
    let mut recomputed = RistrettoPoint::default();
    let mut two_pow_i = Scalar::ONE;
    for b_i in &proof.bit_commits {
        recomputed += two_pow_i * b_i;
        two_pow_i += two_pow_i;
    }
    recomputed == *commitment
}

// ───────── Chaum-Pedersen OR-proof helpers ─────────────────────────

/// Prove that `B = bit*G + s*H` where bit ∈ {0, 1}.
///
/// OR-proof with slot_0 = "B opens to 0" and slot_1 = "B opens to 1".
/// The prover REAL-signs the slot matching `bit` and SIMULATES the
/// other slot. Fiat-Shamir binds both halves via a joint challenge.
fn prove_bit_or(
    params: &PedersenParams,
    commitment: &RistrettoPoint,
    bit: u64,
    s: &Scalar,
) -> BitOrProof {
    // Slot statements (for the verifier):
    //   slot 0: knowledge of r such that B = r*H           (bit = 0)
    //   slot 1: knowledge of r such that B - G = r*H       (bit = 1)
    //
    // Sigma-protocol outline:
    //   - Pick random w for the REAL slot; `a_real = w*H`.
    //   - Pick random (c_sim, r_sim) for the SIMULATED slot;
    //     compute `a_sim = r_sim*H - c_sim*statement_sim` so that the
    //     verifier's check will pass for ANY random (c_sim, r_sim).
    //   - Joint challenge c = H(B || a0 || a1).
    //   - Real challenge c_real = c - c_sim.
    //   - Real response r_real = w + c_real*s.
    //
    // Critical: `a0` is ALWAYS slot 0 in the returned proof, `a1` is
    // ALWAYS slot 1. The verifier does not know which slot is real.

    let w = random_scalar();
    let a_real_point = w * params.h;

    let c_sim = random_scalar();
    let r_sim = random_scalar();

    if bit == 0 {
        // Slot 0 is REAL. Slot 1 is simulated.
        // statement_1 = B - params.g  (for "bit = 1" case, B = params.g + s*h → B-params.g = s*h)
        let statement_1 = commitment - params.g;
        let a1 = r_sim * params.h - c_sim * statement_1;
        let a0 = a_real_point;

        let c = or_challenge(commitment, &a0, &a1);
        let c0 = c - c_sim;       // real challenge for slot 0
        let c1 = c_sim;           // simulated challenge for slot 1
        let r0 = w + c0 * s;      // real response: witness s satisfies B = s*h
        let r1 = r_sim;

        BitOrProof { a0, a1, c0, c1, r0, r1 }
    } else {
        // Slot 1 is REAL. Slot 0 is simulated.
        // statement_0 = B  (for "bit = 0" case, B = 0*g + s*h = s*h)
        let statement_0 = *commitment;
        let a0 = r_sim * params.h - c_sim * statement_0;
        let a1 = a_real_point;

        let c = or_challenge(commitment, &a0, &a1);
        let c0 = c_sim;           // simulated challenge for slot 0
        let c1 = c - c_sim;       // real challenge for slot 1
        let r0 = r_sim;
        let r1 = w + c1 * s;      // real response: witness s satisfies B - params.g = s*h

        BitOrProof { a0, a1, c0, c1, r0, r1 }
    }
}

/// Verify a bit OR-proof.
fn verify_bit_or(
    params: &PedersenParams,
    commitment: &RistrettoPoint,
    proof: &BitOrProof,
) -> bool {
    // Challenge binding: c = c0 + c1 must equal H(a0 || a1 || B).
    let c = or_challenge(commitment, &proof.a0, &proof.a1);
    if proof.c0 + proof.c1 != c {
        return false;
    }

    // Branch 0 check: r0 * H == a0 + c0 * B
    let lhs0 = proof.r0 * params.h;
    let rhs0 = proof.a0 + proof.c0 * commitment;
    if lhs0 != rhs0 {
        return false;
    }

    // Branch 1 check: r1 * h == a1 + c1 * (B - params.g)
    let lhs1 = proof.r1 * params.h;
    let rhs1 = proof.a1 + proof.c1 * (commitment - params.g);
    lhs1 == rhs1
}

fn or_challenge(
    commitment: &RistrettoPoint,
    a0: &RistrettoPoint,
    a1: &RistrettoPoint,
) -> Scalar {
    let hash = Sha512::new()
        .chain_update(b"specter-range-bit-or:")
        .chain_update(commitment.compress().as_bytes())
        .chain_update(a0.compress().as_bytes())
        .chain_update(a1.compress().as_bytes())
        .finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit_u64(params: &PedersenParams, v: u64, r: &Scalar) -> RistrettoPoint {
        params.commit(&Scalar::from(v), r)
    }

    #[test]
    fn test_bit_or_proof_zero_isolated() {
        let params = PedersenParams::new();
        let s = random_scalar();
        let b = params.commit(&Scalar::from(0u64), &s);
        let proof = prove_bit_or(&params, &b, 0, &s);
        assert!(verify_bit_or(&params, &b, &proof));
    }

    #[test]
    fn test_bit_or_proof_one_isolated() {
        let params = PedersenParams::new();
        let s = random_scalar();
        let b = params.commit(&Scalar::from(1u64), &s);

        // Manual sanity check: B - params.g should equal s*params.h
        // for bit=1 (because B = 1*params.g + s*params.h).
        let b_minus_g = b - params.g;
        let s_h = s * params.h;
        assert_eq!(
            b_minus_g, s_h,
            "B - params.g != s*params.h — Pedersen commit has unexpected form"
        );

        let proof = prove_bit_or(&params, &b, 1, &s);
        assert!(verify_bit_or(&params, &b, &proof));
    }

    #[test]
    fn test_range_proof_zero() {
        let params = PedersenParams::new();
        let r = random_scalar();
        let c = commit_u64(&params, 0, &r);
        let proof = prove_range_64(&params, 0, &r);
        assert!(verify_range_64(&params, &c, &proof));
    }

    #[test]
    fn test_range_proof_one() {
        let params = PedersenParams::new();
        let r = random_scalar();
        let c = commit_u64(&params, 1, &r);
        let proof = prove_range_64(&params, 1, &r);
        assert!(verify_range_64(&params, &c, &proof));
    }

    #[test]
    fn test_range_proof_max_u64() {
        let params = PedersenParams::new();
        let r = random_scalar();
        let v = u64::MAX;
        let c = commit_u64(&params, v, &r);
        let proof = prove_range_64(&params, v, &r);
        assert!(verify_range_64(&params, &c, &proof));
    }

    #[test]
    fn test_range_proof_mid() {
        let params = PedersenParams::new();
        let r = random_scalar();
        for v in [42u64, 1000, 1 << 30, 1 << 60, (1u64 << 63) | 1] {
            let c = commit_u64(&params, v, &r);
            let proof = prove_range_64(&params, v, &r);
            assert!(
                verify_range_64(&params, &c, &proof),
                "range proof failed for v={}",
                v
            );
        }
    }

    #[test]
    fn test_range_proof_wrong_commitment_rejected() {
        let params = PedersenParams::new();
        let r = random_scalar();
        let c = commit_u64(&params, 42, &r);
        let c_wrong = commit_u64(&params, 99, &r);
        let proof = prove_range_64(&params, 42, &r);
        assert!(!verify_range_64(&params, &c_wrong, &proof));
    }

    #[test]
    fn test_range_proof_tampered_bit_proof_rejected() {
        let params = PedersenParams::new();
        let r = random_scalar();
        let c = commit_u64(&params, 42, &r);
        let mut proof = prove_range_64(&params, 42, &r);
        // Flip a byte inside one of the bit OR-proof scalars.
        let mut s_bytes = *proof.bit_proofs[3].r0.as_bytes();
        s_bytes[0] ^= 0x01;
        proof.bit_proofs[3].r0 = Scalar::from_bytes_mod_order(s_bytes);
        assert!(!verify_range_64(&params, &c, &proof));
    }

    #[test]
    fn test_range_proof_tampered_bit_commit_rejected() {
        let params = PedersenParams::new();
        let r = random_scalar();
        let c = commit_u64(&params, 42, &r);
        let mut proof = prove_range_64(&params, 42, &r);
        proof.bit_commits[0] += params.g;
        assert!(!verify_range_64(&params, &c, &proof));
    }

    #[test]
    fn test_range_proof_missing_bits_rejected() {
        let params = PedersenParams::new();
        let r = random_scalar();
        let c = commit_u64(&params, 42, &r);
        let mut proof = prove_range_64(&params, 42, &r);
        proof.bit_commits.pop();
        assert!(!verify_range_64(&params, &c, &proof));
    }
}
