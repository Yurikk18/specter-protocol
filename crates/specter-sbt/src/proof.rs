//! NIZK proofs used by the Symmetric Blind Token scheme.
//!
//! Two proofs:
//!
//! 1. **`DdhEqualityProof`** — Chaum-Pedersen proof of discrete-log
//!    equality. Given generators `G, H` and points `A, B`, proves
//!    `∃ x : A = G·x ∧ B = H·x`. Used by trustees to prove each OPRF
//!    share evaluation is consistent with its published commitment.
//!
//! 2. **`TokenProof`** — Schnorr proof of knowledge of a Pedersen
//!    commitment opening plus binding to the unblinded OPRF tag.
//!    Given commitment `C = g^s · h^r` and tag `T = P·k` with
//!    `P = H2C(C)`, proves `∃ s, r : C = g^s · h^r`. The Fiat-Shamir
//!    transcript includes `T` and `P` so the proof is only valid for
//!    the same `(C, T)` pair the signer bound.
//!
//! Both proofs use the SHAKE-256 `Transcript` for Fiat-Shamir.

use crate::transcript::Transcript;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use specter_primitives::pedersen::PedersenParams;
use subtle::ConstantTimeEq;

/// Chaum-Pedersen DDH-equality proof.
///
/// Statement: `∃ x : A = G·x ∧ B = H·x` for public `G, H, A, B`.
///
/// Transcript is bound with a `session_id` and trustee index so two
/// trustees producing evaluations in parallel cannot have their
/// proofs swapped without detection, and so a proof from session A
/// cannot be replayed in session B.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DdhEqualityProof {
    /// `t_G = G · w` (commitment over base G).
    pub t_g: RistrettoPoint,
    /// `t_H = H · w` (commitment over base H).
    pub t_h: RistrettoPoint,
    /// Response `z = w + c · x`.
    pub z: Scalar,
}

impl DdhEqualityProof {
    /// Prove the statement. Witness is `x`, which must satisfy
    /// `A = G·x` and `B = H·x`.
    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        x: &Scalar,
        g: &RistrettoPoint,
        h: &RistrettoPoint,
        a: &RistrettoPoint, // = G·x
        b: &RistrettoPoint, // = H·x
        session_id: &[u8],
        trustee_index: u32,
    ) -> Self {
        // Re-draw until w ≠ 0 to avoid a degenerate transcript where
        // `z = c·x` would directly leak the witness.
        let mut w = Scalar::random(rng);
        while w == Scalar::ZERO {
            w = Scalar::random(rng);
        }
        let t_g = g * w;
        let t_h = h * w;

        let mut tr = Transcript::new(b"sbt-ddh-eq");
        tr.append_bytes(b"session", session_id);
        tr.append_bytes(b"trustee", &trustee_index.to_be_bytes());
        tr.append_point(b"G", g);
        tr.append_point(b"H", h);
        tr.append_point(b"A", a);
        tr.append_point(b"B", b);
        tr.append_point(b"T_G", &t_g);
        tr.append_point(b"T_H", &t_h);
        let c = tr.challenge_scalar(b"c");

        let z = w + c * x;
        Self { t_g, t_h, z }
    }

    /// Verify the statement.
    ///
    /// Rejects identity inputs for `g, h, a, b` — with all-identity
    /// inputs the Chaum-Pedersen equations trivially hold for any
    /// `(c, z)`, so accepting them would let a malicious trustee
    /// inject a zero-witness share and poison the Lagrange combine.
    pub fn verify(
        &self,
        g: &RistrettoPoint,
        h: &RistrettoPoint,
        a: &RistrettoPoint,
        b: &RistrettoPoint,
        session_id: &[u8],
        trustee_index: u32,
    ) -> Result<(), DdhEqualityError> {
        let identity = RistrettoPoint::default();
        if g == &identity
            || h == &identity
            || a == &identity
            || b == &identity
            || self.t_g == identity
            || self.t_h == identity
        {
            return Err(DdhEqualityError::IdentityInput);
        }
        let mut tr = Transcript::new(b"sbt-ddh-eq");
        tr.append_bytes(b"session", session_id);
        tr.append_bytes(b"trustee", &trustee_index.to_be_bytes());
        tr.append_point(b"G", g);
        tr.append_point(b"H", h);
        tr.append_point(b"A", a);
        tr.append_point(b"B", b);
        tr.append_point(b"T_G", &self.t_g);
        tr.append_point(b"T_H", &self.t_h);
        let c = tr.challenge_scalar(b"c");

        let lhs_g = g * self.z;
        let rhs_g = self.t_g + a * c;
        let lhs_h = h * self.z;
        let rhs_h = self.t_h + b * c;

        // Constant-time equality.
        let g_ok = lhs_g.compress().as_bytes().ct_eq(rhs_g.compress().as_bytes());
        let h_ok = lhs_h.compress().as_bytes().ct_eq(rhs_h.compress().as_bytes());

        if bool::from(g_ok & h_ok) {
            Ok(())
        } else {
            Err(DdhEqualityError::VerifyFailed)
        }
    }
}

/// Error produced by DDH-equality verification.
#[derive(Debug, thiserror::Error)]
pub enum DdhEqualityError {
    /// The sigma-protocol equations did not hold.
    #[error("DDH equality proof failed")]
    VerifyFailed,
    /// One of the statement points is the identity (rejected).
    #[error("DDH equality input includes identity point")]
    IdentityInput,
}

/// Schnorr NIZK proof of knowledge of a Pedersen commitment opening,
/// bound to the OPRF tag so a signer cannot be tricked into signing
/// one commitment and having the proof accepted for another.
///
/// Statement: `∃ s, r : C = params.g · s + params.h · r` and the
/// Fiat-Shamir transcript includes the tag `T` and the H2C input
/// point `P`, so the proof is transitively bound to the specific
/// OPRF evaluation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenProof {
    /// `t = params.g · w_s + params.h · w_r`.
    pub t: RistrettoPoint,
    /// `z_s = w_s + c · s`.
    pub z_s: Scalar,
    /// `z_r = w_r + c · r`.
    pub z_r: Scalar,
}

impl TokenProof {
    /// Prove knowledge of `(s, r)` with `commitment = g·s + h·r`,
    /// binding the proof to `(p, tag, y)` via the transcript. The
    /// aggregate OPRF public key `y` prevents cross-key replay of
    /// the token.
    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: CryptoRng + RngCore>(
        rng: &mut R,
        params: &PedersenParams,
        commitment: &RistrettoPoint,
        p: &RistrettoPoint,
        tag: &RistrettoPoint,
        s: &Scalar,
        r: &Scalar,
        context: &[u8],
        y: &RistrettoPoint,
    ) -> Self {
        // Re-draw zero nonces (probability 2⁻²⁵² per draw).
        let mut w_s = Scalar::random(rng);
        while w_s == Scalar::ZERO {
            w_s = Scalar::random(rng);
        }
        let mut w_r = Scalar::random(rng);
        while w_r == Scalar::ZERO {
            w_r = Scalar::random(rng);
        }
        let t = params.g * w_s + params.h * w_r;

        let mut tr = Transcript::new(b"sbt-token-pok-v2");
        tr.append_bytes(b"ctx", context);
        tr.append_point(b"gen_g", &params.g);
        tr.append_point(b"gen_h", &params.h);
        tr.append_point(b"Y", y);
        tr.append_point(b"C", commitment);
        tr.append_point(b"P", p);
        tr.append_point(b"T", tag);
        tr.append_point(b"t", &t);
        let c = tr.challenge_scalar(b"c");

        let z_s = w_s + c * s;
        let z_r = w_r + c * r;
        Self { t, z_s, z_r }
    }

    /// Verify the proof.
    ///
    /// Rejects any identity-point input — see `DdhEqualityProof::verify`
    /// for the underlying motivation.
    pub fn verify(
        &self,
        params: &PedersenParams,
        commitment: &RistrettoPoint,
        p: &RistrettoPoint,
        tag: &RistrettoPoint,
        context: &[u8],
        y: &RistrettoPoint,
    ) -> Result<(), TokenProofError> {
        let identity = RistrettoPoint::default();
        if commitment == &identity
            || p == &identity
            || tag == &identity
            || y == &identity
            || self.t == identity
        {
            return Err(TokenProofError::IdentityInput);
        }
        let mut tr = Transcript::new(b"sbt-token-pok-v2");
        tr.append_bytes(b"ctx", context);
        tr.append_point(b"gen_g", &params.g);
        tr.append_point(b"gen_h", &params.h);
        tr.append_point(b"Y", y);
        tr.append_point(b"C", commitment);
        tr.append_point(b"P", p);
        tr.append_point(b"T", tag);
        tr.append_point(b"t", &self.t);
        let c = tr.challenge_scalar(b"c");

        let lhs = params.g * self.z_s + params.h * self.z_r;
        let rhs = self.t + commitment * c;

        let ok = lhs.compress().as_bytes().ct_eq(rhs.compress().as_bytes());
        if bool::from(ok) {
            Ok(())
        } else {
            Err(TokenProofError::VerifyFailed)
        }
    }
}

/// Error produced by `TokenProof::verify`.
#[derive(Debug, thiserror::Error)]
pub enum TokenProofError {
    /// The Schnorr check did not balance.
    #[error("token NIZK proof failed")]
    VerifyFailed,
    /// One of the statement points is the identity (rejected).
    #[error("token proof input includes identity point")]
    IdentityInput,
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
    use rand::rngs::OsRng;

    #[test]
    fn ddh_eq_roundtrip() {
        let mut rng = OsRng;
        let x = Scalar::random(&mut rng);
        let h = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"test-h");
        let a = G * x;
        let b = h * x;

        let proof = DdhEqualityProof::prove(&mut rng, &x, &G, &h, &a, &b, b"sid", 1);
        proof.verify(&G, &h, &a, &b, b"sid", 1).unwrap();
    }

    #[test]
    fn ddh_eq_fails_on_wrong_witness() {
        let mut rng = OsRng;
        let x_real = Scalar::random(&mut rng);
        let x_wrong = Scalar::random(&mut rng);
        let h = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"h");
        let a = G * x_real;
        let b = h * x_real;

        let bad = DdhEqualityProof::prove(&mut rng, &x_wrong, &G, &h, &a, &b, b"sid", 1);
        assert!(bad.verify(&G, &h, &a, &b, b"sid", 1).is_err());
    }

    #[test]
    fn ddh_eq_fails_on_session_mismatch() {
        let mut rng = OsRng;
        let x = Scalar::random(&mut rng);
        let h = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"h");
        let a = G * x;
        let b = h * x;
        let proof = DdhEqualityProof::prove(&mut rng, &x, &G, &h, &a, &b, b"sid-A", 1);
        assert!(proof.verify(&G, &h, &a, &b, b"sid-B", 1).is_err());
    }

    #[test]
    fn ddh_eq_fails_on_trustee_swap() {
        let mut rng = OsRng;
        let x = Scalar::random(&mut rng);
        let h = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"h");
        let a = G * x;
        let b = h * x;
        let proof = DdhEqualityProof::prove(&mut rng, &x, &G, &h, &a, &b, b"sid", 1);
        assert!(proof.verify(&G, &h, &a, &b, b"sid", 2).is_err());
    }

    #[test]
    fn ddh_eq_fails_when_b_tampered() {
        let mut rng = OsRng;
        let x = Scalar::random(&mut rng);
        let h = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"h");
        let a = G * x;
        let b = h * x;
        let proof = DdhEqualityProof::prove(&mut rng, &x, &G, &h, &a, &b, b"sid", 1);
        let tampered_b = b + G; // add basepoint — now B ≠ H·x
        assert!(proof.verify(&G, &h, &a, &tampered_b, b"sid", 1).is_err());
    }

    #[test]
    fn token_proof_roundtrip() {
        let mut rng = OsRng;
        let params = PedersenParams::new();
        let s = Scalar::random(&mut rng);
        let r = Scalar::random(&mut rng);
        let c = params.g * s + params.h * r;
        let p = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"p");
        let k = Scalar::random(&mut rng);
        let tag = p * k;
        let y = G * k;

        let proof = TokenProof::prove(&mut rng, &params, &c, &p, &tag, &s, &r, b"ctx", &y);
        proof.verify(&params, &c, &p, &tag, b"ctx", &y).unwrap();
    }

    #[test]
    fn token_proof_fails_on_wrong_tag() {
        let mut rng = OsRng;
        let params = PedersenParams::new();
        let s = Scalar::random(&mut rng);
        let r = Scalar::random(&mut rng);
        let c = params.g * s + params.h * r;
        let p = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"p");
        let k = Scalar::random(&mut rng);
        let tag = p * k;
        let y = G * k;

        let proof = TokenProof::prove(&mut rng, &params, &c, &p, &tag, &s, &r, b"ctx", &y);
        let fake_tag = p * Scalar::random(&mut rng);
        assert!(proof
            .verify(&params, &c, &p, &fake_tag, b"ctx", &y)
            .is_err());
    }

    #[test]
    fn token_proof_fails_on_wrong_commitment() {
        let mut rng = OsRng;
        let params = PedersenParams::new();
        let s = Scalar::random(&mut rng);
        let r = Scalar::random(&mut rng);
        let c_real = params.g * s + params.h * r;
        let p = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"p");
        let k = Scalar::random(&mut rng);
        let tag = p * k;
        let y = G * k;

        let proof = TokenProof::prove(&mut rng, &params, &c_real, &p, &tag, &s, &r, b"ctx", &y);
        // Verify against a different commitment.
        let c_fake = params.g * Scalar::random(&mut rng) + params.h * Scalar::random(&mut rng);
        assert!(proof.verify(&params, &c_fake, &p, &tag, b"ctx", &y).is_err());
    }

    #[test]
    fn token_proof_context_binding() {
        let mut rng = OsRng;
        let params = PedersenParams::new();
        let s = Scalar::random(&mut rng);
        let r = Scalar::random(&mut rng);
        let c = params.g * s + params.h * r;
        let p = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"p");
        let k = Scalar::random(&mut rng);
        let tag = p * k;
        let y = G * k;

        let proof = TokenProof::prove(&mut rng, &params, &c, &p, &tag, &s, &r, b"ctx-A", &y);
        assert!(proof.verify(&params, &c, &p, &tag, b"ctx-B", &y).is_err());
    }

    #[test]
    fn token_proof_fails_on_wrong_public_key() {
        // Key-binding test: a token minted under Y_A must not verify
        // against an observer expecting key Y_B.
        let mut rng = OsRng;
        let params = PedersenParams::new();
        let s = Scalar::random(&mut rng);
        let r = Scalar::random(&mut rng);
        let c = params.g * s + params.h * r;
        let p = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"p");
        let k_a = Scalar::random(&mut rng);
        let tag = p * k_a;
        let y_a = G * k_a;
        let y_b = G * Scalar::random(&mut rng);

        let proof = TokenProof::prove(&mut rng, &params, &c, &p, &tag, &s, &r, b"ctx", &y_a);
        assert!(proof.verify(&params, &c, &p, &tag, b"ctx", &y_a).is_ok());
        assert!(proof.verify(&params, &c, &p, &tag, b"ctx", &y_b).is_err());
    }
}
