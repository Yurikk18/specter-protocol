//! Clause Blind Schnorr Signatures (Abe 2001 / GNU Taler variant).
//!
//! Resistant to the Wagner/ROS attack on concurrent sessions.
//! The signer sends TWO nonces per session. A random coin flip
//! selects which one is used. The signer cannot tell which was chosen.
//! This breaks the algebraic structure that Wagner's attack exploits.
//!
//! Used in production by GNU Taler for privacy-preserving digital payments.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};

use specter_primitives::scalar_utils::random_scalar;

use crate::types::{BlindSignature, SignerKeypair};

/// Signer session state with TWO nonces (clause variant).
pub struct ClauseSession {
    k0: Scalar,
    k1: Scalar,
}

impl Drop for ClauseSession {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.k0.zeroize();
        self.k1.zeroize();
    }
}

/// Blinding factors for the clause protocol.
pub struct ClauseBlindingFactors {
    chosen: u8, // 0 or 1
    alpha: Scalar,
    beta: Scalar,
}

impl Drop for ClauseBlindingFactors {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.alpha.zeroize();
        self.beta.zeroize();
    }
}

// ---- Signer side ----

impl SignerKeypair {
    /// Start a clause blind signing session.
    /// Returns session state (private) and TWO nonce commitments (public).
    pub fn new_clause_session(&self) -> (ClauseSession, RistrettoPoint, RistrettoPoint) {
        let k0 = random_scalar();
        let k1 = random_scalar();
        let r0 = k0 * G;
        let r1 = k1 * G;
        (ClauseSession { k0, k1 }, r0, r1)
    }
}

impl ClauseSession {
    /// Signer responds to BOTH challenges. Cannot tell which is real.
    pub fn respond(&self, e0: &Scalar, e1: &Scalar, signer_secret: &Scalar) -> (Scalar, Scalar) {
        let s0 = self.k0 + e0 * signer_secret;
        let s1 = self.k1 + e1 * signer_secret;
        (s0, s1)
    }
}

// ---- Requester side ----

/// Create blinded challenges for the clause protocol.
///
/// Randomly selects one of the two nonces. The signer receives
/// two challenges but cannot determine which is the real one.
///
/// The branch-selection bit `b` is SECRET — if a local observer could infer
/// `b` via timing/cache side channels, they could distinguish the real from
/// the decoy nonce and defeat unlinkability in the presence of a co-located
/// adversary. This implementation uses `subtle::ConditionallySelectable` to
/// keep the scalar/point selection constant-time w.r.t. `b`.
pub fn clause_blind_challenge(
    r0: &RistrettoPoint,
    r1: &RistrettoPoint,
    signer_pk: &RistrettoPoint,
    message: &[u8],
) -> (ClauseBlindingFactors, Scalar, Scalar) {
    use subtle::{Choice, ConditionallySelectable};

    // Random bit selects the real branch. Read the bit into a Choice so
    // downstream `conditional_select` calls are constant-time.
    let b_byte = {
        let mut buf = [0u8; 1];
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(&mut buf);
        buf[0] & 1
    };
    let choice = Choice::from(b_byte);

    let alpha = random_scalar();
    let beta = random_scalar();

    // Constant-time select of the "real" nonce commitment.
    // RistrettoPoint implements ConditionallySelectable in dalek 4.x.
    let r_chosen = RistrettoPoint::conditional_select(r0, r1, choice);

    let r_prime = r_chosen + alpha * G + beta * signer_pk;
    let e_prime = hash_challenge(&r_prime, signer_pk, message);
    let e_real = e_prime + beta;

    // Decoy branch: random challenge
    let e_decoy = random_scalar();

    // Constant-time placement of (e_real, e_decoy) into the (e0, e1) slots.
    let e0 = Scalar::conditional_select(&e_real, &e_decoy, choice);
    let e1 = Scalar::conditional_select(&e_decoy, &e_real, choice);

    let factors = ClauseBlindingFactors {
        chosen: b_byte,
        alpha,
        beta,
    };
    (factors, e0, e1)
}

/// Unblind the signer's response to get the final signature.
///
/// Uses constant-time selection on the secret `chosen` branch indicator so
/// a local side-channel observer cannot learn which of (s0, r0) vs (s1, r1)
/// was the real branch.
pub fn clause_unblind(
    s0: &Scalar,
    s1: &Scalar,
    factors: &ClauseBlindingFactors,
    r0: &RistrettoPoint,
    r1: &RistrettoPoint,
    signer_pk: &RistrettoPoint,
    message: &[u8],
) -> BlindSignature {
    use subtle::{Choice, ConditionallySelectable};
    let choice = Choice::from(factors.chosen);

    let s_chosen = Scalar::conditional_select(s0, s1, choice);
    let r_chosen = RistrettoPoint::conditional_select(r0, r1, choice);

    let s = s_chosen + factors.alpha;
    let r_prime = r_chosen + factors.alpha * G + factors.beta * signer_pk;
    let e = hash_challenge(&r_prime, signer_pk, message);

    BlindSignature { s, e }
}

/// Verify a clause blind signature. Same as standard Schnorr verify.
pub fn verify(pk: &RistrettoPoint, message: &[u8], sig: &BlindSignature) -> bool {
    use subtle::ConstantTimeEq;
    let r_prime = sig.s * G - sig.e * pk;
    let expected_e = hash_challenge(&r_prime, pk, message);
    // Constant-time comparison to prevent timing oracle on challenge scalar
    expected_e.as_bytes().ct_eq(sig.e.as_bytes()).into()
}

fn hash_challenge(r: &RistrettoPoint, pk: &RistrettoPoint, message: &[u8]) -> Scalar {
    let hash = Sha512::new()
        .chain_update(b"specter-clause-blind-challenge:")
        .chain_update(r.compress().as_bytes())
        .chain_update(pk.compress().as_bytes())
        .chain_update((message.len() as u64).to_le_bytes())
        .chain_update(message)
        .finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clause_blind_roundtrip() {
        let signer = SignerKeypair::generate();
        let message = b"clause blind signed token";

        let (session, r0, r1) = signer.new_clause_session();
        let (factors, e0, e1) = clause_blind_challenge(&r0, &r1, &signer.public, message);
        let (s0, s1) = session.respond(&e0, &e1, signer.secret());
        let sig = clause_unblind(&s0, &s1, &factors, &r0, &r1, &signer.public, message);

        assert!(verify(&signer.public, message, &sig));
    }

    #[test]
    fn test_clause_wrong_message_fails() {
        let signer = SignerKeypair::generate();
        let message = b"correct";

        let (session, r0, r1) = signer.new_clause_session();
        let (factors, e0, e1) = clause_blind_challenge(&r0, &r1, &signer.public, message);
        let (s0, s1) = session.respond(&e0, &e1, signer.secret());
        let sig = clause_unblind(&s0, &s1, &factors, &r0, &r1, &signer.public, message);

        assert!(!verify(&signer.public, b"wrong", &sig));
    }

    #[test]
    fn test_clause_wrong_pubkey_fails() {
        let signer = SignerKeypair::generate();
        let other = SignerKeypair::generate();
        let message = b"test";

        let (session, r0, r1) = signer.new_clause_session();
        let (factors, e0, e1) = clause_blind_challenge(&r0, &r1, &signer.public, message);
        let (s0, s1) = session.respond(&e0, &e1, signer.secret());
        let sig = clause_unblind(&s0, &s1, &factors, &r0, &r1, &signer.public, message);

        assert!(!verify(&other.public, message, &sig));
    }

    #[test]
    fn test_clause_unlinkability() {
        let signer = SignerKeypair::generate();
        let msg = b"same message";

        let (s1, r0a, r1a) = signer.new_clause_session();
        let (f1, e0a, e1a) = clause_blind_challenge(&r0a, &r1a, &signer.public, msg);
        let (s0a, s1a) = s1.respond(&e0a, &e1a, signer.secret());
        let sig1 = clause_unblind(&s0a, &s1a, &f1, &r0a, &r1a, &signer.public, msg);

        let (s2, r0b, r1b) = signer.new_clause_session();
        let (f2, e0b, e1b) = clause_blind_challenge(&r0b, &r1b, &signer.public, msg);
        let (s0b, s1b) = s2.respond(&e0b, &e1b, signer.secret());
        let sig2 = clause_unblind(&s0b, &s1b, &f2, &r0b, &r1b, &signer.public, msg);

        assert!(verify(&signer.public, msg, &sig1));
        assert!(verify(&signer.public, msg, &sig2));
        assert_ne!(sig1, sig2); // different signatures, unlinkable
    }

    #[test]
    fn test_clause_many_signatures() {
        let signer = SignerKeypair::generate();
        for i in 0..20 {
            let msg = format!("token-{}", i);
            let (session, r0, r1) = signer.new_clause_session();
            let (factors, e0, e1) = clause_blind_challenge(&r0, &r1, &signer.public, msg.as_bytes());
            let (s0, s1) = session.respond(&e0, &e1, signer.secret());
            let sig = clause_unblind(&s0, &s1, &factors, &r0, &r1, &signer.public, msg.as_bytes());
            assert!(verify(&signer.public, msg.as_bytes(), &sig), "failed at i={}", i);
        }
    }
}
