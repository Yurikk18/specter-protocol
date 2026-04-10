//! Schnorr Blind Signature Protocol over Ristretto255.
//!
//! Implements the classic 3-move blind signature protocol:
//!
//! 1. **Signer** generates a random nonce k, sends R = k*G to the requester.
//! 2. **Requester** blinds the message: computes blinding factors (alpha, beta),
//!    creates blinded challenge e, sends e to the signer.
//! 3. **Signer** responds with s' = k + e * secret.
//! 4. **Requester** unblinds: computes final signature (s, e').
//!
//! The signer never sees the message or the final signature.
//! The signature is unlinkable - the signer cannot correlate signing sessions
//! with observed signatures.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};

use crate::types::{BlindSignature, SignerKeypair};
use specter_primitives::scalar_utils::random_scalar;

// ─── Signer Side ────────────────────────────────────────────────────────────

/// State of a signing session (held by the signer).
///
/// Contains the secret nonce k. Must not be reused across sessions.
pub struct SignerSession {
    k: Scalar,
}

impl SignerKeypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let secret = random_scalar();
        let public = secret * G;
        Self::from_parts(secret, public)
    }

    /// Start a new blind signing session.
    ///
    /// Returns the session state (kept private) and the commitment R = k*G
    /// which is sent to the requester.
    pub fn new_session(&self) -> (SignerSession, RistrettoPoint) {
        let k = random_scalar();
        let r = k * G;
        (SignerSession { k }, r)
    }
}

impl SignerSession {
    /// Respond to a blinded challenge.
    ///
    /// Computes s' = k + challenge * secret.
    /// The signer does NOT know the actual message being signed.
    pub fn respond(&self, challenge: &Scalar, signer_secret: &Scalar) -> Scalar {
        self.k + challenge * signer_secret
    }
}

// ─── Requester Side ─────────────────────────────────────────────────────────

/// Blinding factors chosen by the requester.
///
/// These are kept secret until unblinding.
pub struct BlindingFactors {
    alpha: Scalar,
    beta: Scalar,
}

/// Blind a challenge for a message.
///
/// Given the signer's commitment R and public key, the requester:
/// 1. Chooses random blinding factors alpha, beta.
/// 2. Computes R' = R + alpha*G + beta*PK  (blinded commitment).
/// 3. Computes e' = H(R' || message)  (challenge for the final signature).
/// 4. Computes e = e' + beta  (blinded challenge sent to the signer).
///
/// Returns the blinding factors (for later unblinding) and the blinded
/// challenge e to send to the signer.
pub fn blind_challenge(
    signer_r: &RistrettoPoint,
    signer_pk: &RistrettoPoint,
    message: &[u8],
) -> (BlindingFactors, Scalar) {
    let alpha = random_scalar();
    let beta = random_scalar();

    // R' = R + alpha*G + beta*PK
    let r_prime = signer_r + alpha * G + beta * signer_pk;

    // e' = H(R' || message)
    let e_prime = hash_challenge(&r_prime, message);

    // e = e' + beta (sent to signer)
    let e_blinded = e_prime + beta;

    let factors = BlindingFactors { alpha, beta };
    (factors, e_blinded)
}

/// Unblind the signer's response to obtain the final signature.
///
/// Given the signer's response s' and the blinding factors:
/// - s = s' + alpha
/// - e = (the e' computed during blinding)
///
/// The result is a valid Schnorr signature (s, e) on the original message,
/// which the signer has never seen.
pub fn unblind_signature(
    s_prime: &Scalar,
    factors: &BlindingFactors,
    signer_r: &RistrettoPoint,
    signer_pk: &RistrettoPoint,
    message: &[u8],
) -> BlindSignature {
    let s = s_prime + factors.alpha;

    // Recompute e' = H(R' || message) where R' = R + alpha*G + beta*PK
    let r_prime = signer_r + factors.alpha * G + factors.beta * signer_pk;
    let e = hash_challenge(&r_prime, message);

    BlindSignature { s, e }
}

// ─── Verification ───────────────────────────────────────────────────────────

/// Verify a blind Schnorr signature.
///
/// Checks that s*G == R' + e*PK, where R' is recovered as s*G - e*PK,
/// and then verifies H(R' || message) == e.
///
/// The verifier does NOT need to know the blinding factors.
pub fn verify(pk: &RistrettoPoint, message: &[u8], sig: &BlindSignature) -> bool {
    // Recover R' = s*G - e*PK
    let r_prime = sig.s * G - sig.e * pk;

    // Check: H(R' || message) == e
    let expected_e = hash_challenge(&r_prime, message);
    expected_e == sig.e
}

// ─── Internal ───────────────────────────────────────────────────────────────

/// Hash a Ristretto point and message to a scalar challenge.
///
/// H(R || message) using SHA-512 reduced to a scalar.
fn hash_challenge(r: &RistrettoPoint, message: &[u8]) -> Scalar {
    let hash = Sha512::new()
        .chain_update(b"specter-blind-sig-challenge:")
        .chain_update(r.compress().as_bytes())
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
    fn test_full_protocol_roundtrip() {
        let signer = SignerKeypair::generate();
        let message = b"transfer 100 units to Alice";

        // Step 1: Signer creates session
        let (session, r) = signer.new_session();

        // Step 2: Requester blinds the challenge
        let (factors, blinded_challenge) = blind_challenge(&r, &signer.public, message);

        // Step 3: Signer responds
        let s_prime = session.respond(&blinded_challenge, signer.secret());

        // Step 4: Requester unblinds
        let sig = unblind_signature(&s_prime, &factors, &r, &signer.public, message);

        // Verify
        assert!(verify(&signer.public, message, &sig));
    }

    #[test]
    fn test_wrong_message_fails() {
        let signer = SignerKeypair::generate();
        let message = b"correct message";

        let (session, r) = signer.new_session();
        let (factors, blinded_challenge) = blind_challenge(&r, &signer.public, message);
        let s_prime = session.respond(&blinded_challenge, signer.secret());
        let sig = unblind_signature(&s_prime, &factors, &r, &signer.public, message);

        // Verification with wrong message must fail
        assert!(!verify(&signer.public, b"wrong message", &sig));
    }

    #[test]
    fn test_wrong_pubkey_fails() {
        let signer = SignerKeypair::generate();
        let other = SignerKeypair::generate();
        let message = b"some message";

        let (session, r) = signer.new_session();
        let (factors, blinded_challenge) = blind_challenge(&r, &signer.public, message);
        let s_prime = session.respond(&blinded_challenge, signer.secret());
        let sig = unblind_signature(&s_prime, &factors, &r, &signer.public, message);

        // Verification against a different public key must fail
        assert!(!verify(&other.public, message, &sig));
    }

    #[test]
    fn test_unlinkability_structure() {
        let signer = SignerKeypair::generate();
        let message = b"same message";

        // Two different signing sessions on the same message
        let (session1, r1) = signer.new_session();
        let (factors1, bc1) = blind_challenge(&r1, &signer.public, message);
        let s1 = session1.respond(&bc1, signer.secret());
        let sig1 = unblind_signature(&s1, &factors1, &r1, &signer.public, message);

        let (session2, r2) = signer.new_session();
        let (factors2, bc2) = blind_challenge(&r2, &signer.public, message);
        let s2 = session2.respond(&bc2, signer.secret());
        let sig2 = unblind_signature(&s2, &factors2, &r2, &signer.public, message);

        // Both signatures are valid
        assert!(verify(&signer.public, message, &sig1));
        assert!(verify(&signer.public, message, &sig2));

        // But they are different (different nonces and blinding factors)
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_different_messages_both_valid() {
        let signer = SignerKeypair::generate();

        let msg1 = b"message one";
        let (s1, r1) = signer.new_session();
        let (f1, bc1) = blind_challenge(&r1, &signer.public, msg1);
        let sp1 = s1.respond(&bc1, signer.secret());
        let sig1 = unblind_signature(&sp1, &f1, &r1, &signer.public, msg1);

        let msg2 = b"message two";
        let (s2, r2) = signer.new_session();
        let (f2, bc2) = blind_challenge(&r2, &signer.public, msg2);
        let sp2 = s2.respond(&bc2, signer.secret());
        let sig2 = unblind_signature(&sp2, &f2, &r2, &signer.public, msg2);

        assert!(verify(&signer.public, msg1, &sig1));
        assert!(verify(&signer.public, msg2, &sig2));

        // Cross-verification fails
        assert!(!verify(&signer.public, msg1, &sig2));
        assert!(!verify(&signer.public, msg2, &sig1));
    }

    #[test]
    fn test_many_signatures_all_valid() {
        let signer = SignerKeypair::generate();
        for i in 0..20 {
            let message = format!("token-{}", i);
            let (session, r) = signer.new_session();
            let (factors, bc) = blind_challenge(&r, &signer.public, message.as_bytes());
            let sp = session.respond(&bc, signer.secret());
            let sig = unblind_signature(&sp, &factors, &r, &signer.public, message.as_bytes());
            assert!(verify(&signer.public, message.as_bytes(), &sig), "failed at i={}", i);
        }
    }
}
