//! Schnorr Blind Signature Protocol over Ristretto255.
//!
//! SECURITY WARNING: Standard blind Schnorr is vulnerable to the Wagner/ROS
//! attack when a signer allows concurrent sessions (poly(log n) sessions
//! enable forgery). The signer MUST NOT allow more than one open session at
//! a time with this protocol. For concurrent-safe signing, use the clause
//! blind variant in `clause_blind.rs` (Abe 2001 / GNU Taler).
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

impl Drop for SignerSession {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.k.zeroize();
    }
}

/// A rate-limited signer that enforces at most one concurrent session.
///
/// Standard blind Schnorr is vulnerable to the Wagner/ROS attack when
/// multiple sessions are open concurrently. This wrapper ensures only
/// one session can be active at a time, closing the attack surface.
///
/// The session lifecycle is tied to a [`SessionGuard`] RAII handle.
/// While the guard is alive, the borrow checker prevents opening a
/// second session (the guard holds `&mut self`). When the guard is
/// dropped (by explicit drop, scope exit, or panic unwind), the
/// session is automatically marked inactive.
pub struct RateLimitedSigner {
    keypair: SignerKeypair,
    session_active: bool,
}

/// RAII guard that automatically releases the session on drop.
///
/// Holds a mutable borrow on the [`RateLimitedSigner`], so the Rust
/// borrow checker prevents opening a second session while this guard
/// is alive. Dropping the guard (explicitly or via scope exit/panic)
/// marks the session as inactive.
pub struct SessionGuard<'a> {
    signer: &'a mut RateLimitedSigner,
    /// The session state (contains the secret nonce k).
    pub session: SignerSession,
    /// The signer's nonce commitment R = k * G (sent to the requester).
    pub commitment: RistrettoPoint,
}

impl<'a> Drop for SessionGuard<'a> {
    fn drop(&mut self) {
        self.signer.session_active = false;
    }
}

impl RateLimitedSigner {
    /// Create a new rate-limited signer.
    pub fn new(keypair: SignerKeypair) -> Self {
        Self { keypair, session_active: false }
    }

    /// Start a new session. Returns None if a session is already active.
    ///
    /// The returned [`SessionGuard`] holds `&mut self`, so the borrow
    /// checker prevents a second call while the guard exists. The guard
    /// automatically releases the session on drop.
    pub fn new_session(&mut self) -> Option<SessionGuard<'_>> {
        if self.session_active {
            return None; // ROS protection: only one session at a time
        }
        self.session_active = true;
        let k = random_scalar();
        let r = k * G;
        Some(SessionGuard {
            signer: self,
            session: SignerSession { k },
            commitment: r,
        })
    }

    /// Complete the session (must be called after respond).
    ///
    /// Prefer dropping the [`SessionGuard`] instead of calling this
    /// directly. This method exists for backward compatibility.
    pub fn end_session(&mut self) {
        self.session_active = false;
    }

    /// Access the keypair for verification.
    pub fn keypair(&self) -> &SignerKeypair {
        &self.keypair
    }

    /// Access the public key.
    pub fn public(&self) -> &RistrettoPoint {
        &self.keypair.public
    }
}

impl SignerKeypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let secret = random_scalar();
        let public = secret * G;
        Self::from_parts(secret, public)
    }

    /// Start a new blind signing session — **TEST/INTERNAL ONLY**.
    ///
    /// # Security Warning
    ///
    /// This does NOT enforce concurrency limits. Plain blind Schnorr is
    /// vulnerable to the Wagner/ROS attack (Benhamouda et al. 2021) when
    /// poly(log n) sessions run concurrently — an attacker solving the ROS
    /// problem can forge `ℓ+1` signatures from `ℓ` sessions.
    ///
    /// Production callers MUST use [`RateLimitedSigner::new_session`] which
    /// enforces a single in-flight session, or the [`clause_blind`] variant
    /// which is ROS-resistant by construction (Abe 2001).
    ///
    /// This method is visible only inside the crate (tests, threshold helpers,
    /// clause-blind helpers). External users of the crate cannot call it.
    #[allow(dead_code)] // exercised by #[cfg(test)] units
    pub(crate) fn new_session(&self) -> (SignerSession, RistrettoPoint) {
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

impl Drop for BlindingFactors {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.alpha.zeroize();
        self.beta.zeroize();
    }
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

    // e' = H(R' || PK || message)
    let e_prime = hash_challenge(&r_prime, signer_pk, message);

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

    // Recompute e' = H(R' || PK || message) where R' = R + alpha*G + beta*PK
    let r_prime = signer_r + factors.alpha * G + factors.beta * signer_pk;
    let e = hash_challenge(&r_prime, signer_pk, message);

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
    use subtle::ConstantTimeEq;
    // Recover R' = s*G - e*PK
    let r_prime = sig.s * G - sig.e * pk;

    // Check: H(R' || PK || message) == e (constant-time to prevent timing oracle)
    let expected_e = hash_challenge(&r_prime, pk, message);
    expected_e.as_bytes().ct_eq(sig.e.as_bytes()).into()
}

// ─── Internal ───────────────────────────────────────────────────────────────

/// Hash a Ristretto point, public key, and message to a scalar challenge.
///
/// H(R || PK || msg_len || message) using SHA-512 reduced to a scalar.
/// PK is included in the hash to prevent key-substitution attacks where
/// an adversary forges PK' such that a valid signature for PK also
/// verifies under PK'. This is critical in multi-issuer deployments.
fn hash_challenge(r: &RistrettoPoint, pk: &RistrettoPoint, message: &[u8]) -> Scalar {
    use zeroize::Zeroize;
    let hash = Sha512::new()
        .chain_update(b"specter-blind-sig-challenge:")
        .chain_update(r.compress().as_bytes())
        .chain_update(pk.compress().as_bytes())
        .chain_update((message.len() as u64).to_le_bytes())
        .chain_update(message)
        .finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    s
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

    // ── Concurrent session blocking tests (A5) ─────────────────────────

    /// RateLimitedSigner MUST refuse a second session while the first is
    /// still open. This is the protocol-level defense against the
    /// Wagner/ROS attack on plain blind Schnorr: allowing ℓ ≈ 256
    /// concurrent sessions lets an attacker forge ℓ+1 signatures from
    /// ℓ interactions. Enforcing single-session serializes access and
    /// denies the attacker the required concurrency.
    #[test]
    fn test_rate_limited_signer_blocks_concurrent_session() {
        let kp = SignerKeypair::generate();
        let mut signer = RateLimitedSigner::new(kp);

        {
            // First session opens.
            let first = signer.new_session();
            assert!(first.is_some(), "first session must succeed");
            // SessionGuard holds &mut signer — second session cannot even
            // be attempted while the guard is alive (borrow checker).
            // Drop the guard to release the session.
        }

        // After guard drop, a new session is allowed.
        let second = signer.new_session();
        assert!(second.is_some(), "session after guard drop must succeed");
    }

    /// Many sequential sessions via RAII guards all succeed.
    /// This locks in the "one at a time, but no artificial limit on the
    /// total" invariant.
    #[test]
    fn test_rate_limited_signer_sequential_sessions() {
        let kp = SignerKeypair::generate();
        let mut signer = RateLimitedSigner::new(kp);
        for _ in 0..100 {
            let s = signer.new_session();
            assert!(s.is_some());
            // Guard drops at end of loop iteration → session released.
        }
    }

    /// Thread-based concurrency test: threads race to acquire + release
    /// the signer session via Mutex + RAII guard. Each thread opens a
    /// session, uses it, and lets the guard drop — proving that the
    /// RAII cleanup works correctly under contention.
    #[test]
    fn test_rate_limited_signer_parallel_contention() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let kp = SignerKeypair::generate();
        let signer = Arc::new(Mutex::new(RateLimitedSigner::new(kp)));

        // Spawn contenders — each acquires the Mutex, opens a session
        // (guard drops at end of block → session released), and yields.
        // All must succeed because the guard auto-releases.
        let mut handles = Vec::new();
        for _ in 0..8 {
            let s = Arc::clone(&signer);
            handles.push(thread::spawn(move || {
                let mut g = s.lock().unwrap();
                let guard = g.new_session();
                assert!(guard.is_some(), "session must succeed under mutex");
                // guard drops here → session_active = false
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
    }
}
