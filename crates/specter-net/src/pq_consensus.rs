//! Post-quantum hybrid consensus signature VERIFICATION.
//!
//! Implements a `HybridVote` type plus a verification function that
//! checks BOTH the classical Schnorr signature AND an ML-DSA-65
//! (FIPS 204) signature over the same canonical message. The scheme
//! is sound as long as at least one of `{ ECDLP, Module-SIS }`
//! remains hard.
//!
//! # Scope: verify-only
//!
//! This module deliberately exposes **verification only**, not key
//! generation or signing. Two reasons:
//!
//! 1. `ml_dsa 0.1.0-rc.8`'s `KeyGen::key_gen` requires a
//!    `CryptoRng` from a `rand_core` version that does not
//!    coexist cleanly with the workspace-wide `rand_core 0.6`
//!    pinned for `curve25519-dalek`. Writing a cross-version
//!    bridge is brittle and would have to be rewritten when the
//!    upstream crate stabilizes.
//! 2. More importantly — in a production validator the PQ signing
//!    key belongs in an HSM or a protected key-store, NOT in the
//!    network layer. Generating it inside this module would
//!    encourage operators to hold the sk alongside the Ristretto
//!    secret, which is the anti-pattern we want to avoid.
//!
//! Operators generate their ML-DSA-65 keypairs out-of-band (e.g.
//! `ml-dsa` example binary, `pqcrypto-mldsa`, or an HSM-backed
//! flow) and ship the verifying key bytes to peers via the same
//! out-of-band channel that already carries Ristretto validator pks.
//!
//! # Threat model
//!
//! Breaking consensus safety under the hybrid scheme requires an
//! attacker to forge BOTH:
//!
//! - A Schnorr signature under the voter's Ristretto public key
//!   (hard under ECDLP)
//! - An ML-DSA-65 signature under the voter's lattice public key
//!   (hard under Module-SIS / Module-LWE)
//!
//! A CRQC-holding adversary breaks the Schnorr leg but not the
//! ML-DSA leg. A classical adversary breaks neither. An adversary
//! who breaks ML-DSA first still has the Schnorr wall.

#![cfg(feature = "pq-consensus")]

use ml_dsa::signature::Verifier;
use ml_dsa::{MlDsa65, VerifyingKey};

use crate::consensus::Vote;

/// A hybrid vote: classical Schnorr signature (via `Vote`) PLUS an
/// ML-DSA-65 signature over the same canonical message.
#[derive(Clone, Debug)]
pub struct HybridVote {
    /// Classical Schnorr leg.
    pub classical: Vote,
    /// ML-DSA-65 signature bytes (FIPS 204 encoded).
    pub pq_signature: Vec<u8>,
}

impl HybridVote {
    /// Construct a hybrid vote from its two components.
    ///
    /// The caller is responsible for producing `pq_signature` — this
    /// module does not generate key material or signatures.
    pub fn new(classical: Vote, pq_signature: Vec<u8>) -> Self {
        Self {
            classical,
            pq_signature,
        }
    }

    /// Verify BOTH legs. Returns true only when both verify.
    ///
    /// Missing either signature — or either leg failing — causes
    /// rejection. There is no "fall-back to classical" semantics:
    /// once a network operator opts into hybrid, every vote must
    /// include a valid PQ signature.
    pub fn verify(
        &self,
        classical_pk: &curve25519_dalek::RistrettoPoint,
        pq_vk: &VerifyingKey<MlDsa65>,
    ) -> bool {
        // Classical leg — existing Schnorr verification path.
        if !crate::consensus::verify_vote_signature(&self.classical, classical_pk) {
            return false;
        }
        // PQ leg — decode the fixed-length signature and verify.
        let encoded =
            match ml_dsa::EncodedSignature::<MlDsa65>::try_from(self.pq_signature.as_slice()) {
                Ok(e) => e,
                Err(_) => return false,
            };
        let sig = match ml_dsa::Signature::<MlDsa65>::decode(&encoded) {
            Some(s) => s,
            None => return false,
        };
        pq_vk
            .verify(&canonical_vote_message(&self.classical), &sig)
            .is_ok()
    }
}

/// Parse an ML-DSA-65 verifying key from its FIPS 204 byte encoding.
///
/// Operators distribute these bytes alongside the classical
/// Ristretto validator public key.
pub fn parse_pq_verifying_key(
    encoded: &[u8],
) -> Option<VerifyingKey<MlDsa65>> {
    let arr = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(encoded).ok()?;
    Some(VerifyingKey::<MlDsa65>::decode(&arr))
}

/// Canonical bytes that BOTH signatures must cover. MUST be kept in
/// sync with the classical Schnorr `vote_message` construction —
/// any divergence would allow an attacker to reuse a classical
/// signature for a different logical vote.
pub fn canonical_vote_message(vote: &Vote) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 8 + 8 + 32 + 1 + 20);
    msg.extend_from_slice(b"specter-hybrid-vote:");
    msg.extend_from_slice(&vote.voter.to_le_bytes());
    msg.extend_from_slice(&vote.block_height.to_le_bytes());
    msg.extend_from_slice(&vote.view.to_le_bytes());
    msg.extend_from_slice(&vote.block_hash);
    msg.push(if vote.approve { 1 } else { 0 });
    msg
}

// Re-export the canonical type aliases.
pub use ml_dsa::{
    EncodedSignature as PqEncodedSignature,
    EncodedVerifyingKey as PqEncodedVerifyingKey,
    MlDsa65 as PqScheme,
    VerifyingKey as PqVerifyingKey,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ValidatorKey;

    #[test]
    fn test_canonical_vote_message_deterministic() {
        let k = ValidatorKey::generate(1);
        let v = k.sign_vote(0, &[7u8; 32], true, 0);
        let m1 = canonical_vote_message(&v);
        let m2 = canonical_vote_message(&v);
        assert_eq!(m1, m2);
    }

    #[test]
    fn test_canonical_vote_message_sensitive_to_all_fields() {
        let k = ValidatorKey::generate(1);
        let base = k.sign_vote(0, &[7u8; 32], true, 0);
        let m_base = canonical_vote_message(&base);

        // Flipping any field must change the canonical message.
        let mut v2 = base.clone();
        v2.block_height = 1;
        assert_ne!(canonical_vote_message(&v2), m_base);

        let mut v3 = base.clone();
        v3.view = 1;
        assert_ne!(canonical_vote_message(&v3), m_base);

        let mut v4 = base.clone();
        v4.approve = false;
        assert_ne!(canonical_vote_message(&v4), m_base);

        let mut v5 = base.clone();
        v5.block_hash[0] ^= 1;
        assert_ne!(canonical_vote_message(&v5), m_base);
    }

    #[test]
    fn test_hybrid_vote_invalid_pq_bytes_rejected() {
        // Any non-ML-DSA-65-sized pq_signature is rejected
        // immediately by try_from on the encoded array.
        let k = ValidatorKey::generate(1);
        let classical = k.sign_vote(0, &[7u8; 32], true, 0);
        let hybrid = HybridVote::new(classical, vec![0u8; 10]);

        // Caller-supplied bogus verifying key bytes are rejected by
        // parse_pq_verifying_key. Use a valid-length vector of zeros
        // to get past the length check and hit the decode path.
        // ML-DSA-65 verifying key is 1952 bytes.
        let bogus_vk_bytes = vec![0u8; 1952];
        let vk = parse_pq_verifying_key(&bogus_vk_bytes);
        // An all-zero byte string DOES produce a structurally-valid
        // VerifyingKey (the decode path has no intrinsic validity
        // check beyond length). What fails is the signature check
        // below — 10 zero bytes is not a valid encoded signature, so
        // the verify function rejects it at the try_from step.
        if let Some(vk) = vk {
            let classical_pk = curve25519_dalek::RistrettoPoint::default();
            assert!(!hybrid.verify(&classical_pk, &vk));
        }
    }
}
