//! SHAKE-256 based Fiat-Shamir transcript for SBT NIZK proofs.
//!
//! Uses Keccak sponge (SHAKE-256) so the hash layer is
//! collision-resistant at the 128-bit level and robust against
//! length-extension. Each append is prefixed with an ASCII domain tag
//! and the length of the value in big-endian **u64** — this prevents a
//! colliding concatenation of `("ab","cd")` and `("abc","d")` from
//! producing the same transcript state, a flaw that has previously
//! bitten sigma-protocol compositions. The `u64` width also defends
//! against silent truncation on 64-bit hosts processing adversarial
//! multi-gigabyte payloads.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// A domain-separated Fiat-Shamir transcript.
pub struct Transcript {
    hasher: Shake256,
}

/// Crate-wide domain tag for transcript-based Fiat-Shamir proofs.
/// Distinct from the KDF tag in [`crate::scheme`] to allow the two
/// subsystems to version independently.
pub const SBT_TRANSCRIPT_TAG: &[u8] = b"SPECTER-SBT-TRANSCRIPT-v1/";

impl Transcript {
    /// Build a transcript with a protocol label. Distinct labels
    /// yield independent proof systems.
    pub fn new(label: &'static [u8]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(SBT_TRANSCRIPT_TAG);
        hasher.update(&(label.len() as u64).to_be_bytes());
        hasher.update(label);
        Self { hasher }
    }

    /// Append a labelled byte string.
    pub fn append_bytes(&mut self, tag: &'static [u8], bytes: &[u8]) {
        self.hasher.update(&(tag.len() as u64).to_be_bytes());
        self.hasher.update(tag);
        self.hasher.update(&(bytes.len() as u64).to_be_bytes());
        self.hasher.update(bytes);
    }

    /// Append a Ristretto point in compressed form.
    pub fn append_point(&mut self, tag: &'static [u8], point: &RistrettoPoint) {
        self.append_bytes(tag, point.compress().as_bytes());
    }

    /// Append an already-compressed point.
    pub fn append_compressed(&mut self, tag: &'static [u8], c: &CompressedRistretto) {
        self.append_bytes(tag, c.as_bytes());
    }

    /// Squeeze a challenge scalar uniformly (64 bytes reduced mod l).
    pub fn challenge_scalar(&mut self, tag: &'static [u8]) -> Scalar {
        self.append_bytes(tag, b"");
        let mut xof = self.hasher.clone().finalize_xof();
        // Re-absorb the squeezed value into the sponge so subsequent
        // challenges differ — otherwise two consecutive calls would
        // return identical scalars. Length-prefix the re-absorbed
        // bytes so a future variant of `challenge_*` that squeezes
        // a different length cannot collide.
        let mut buf = [0u8; 64];
        xof.read(&mut buf);
        self.hasher.update(b"__cs_mix__");
        self.hasher.update(&(buf.len() as u64).to_be_bytes());
        self.hasher.update(&buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }

    /// Squeeze an N-byte label (used for nullifiers/tag hashes).
    pub fn challenge_bytes<const N: usize>(&mut self, tag: &'static [u8]) -> [u8; N] {
        self.append_bytes(tag, b"");
        let mut xof = self.hasher.clone().finalize_xof();
        let mut out = [0u8; N];
        xof.read(&mut out);
        self.hasher.update(b"__cb_mix__");
        self.hasher.update(&(out.len() as u64).to_be_bytes());
        self.hasher.update(&out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_labels_give_distinct_challenges() {
        let mut t1 = Transcript::new(b"alpha");
        let mut t2 = Transcript::new(b"beta");
        t1.append_bytes(b"x", b"hello");
        t2.append_bytes(b"x", b"hello");
        assert_ne!(t1.challenge_scalar(b"c"), t2.challenge_scalar(b"c"));
    }

    #[test]
    fn consecutive_challenges_differ() {
        let mut t = Transcript::new(b"alpha");
        let c1 = t.challenge_scalar(b"c");
        let c2 = t.challenge_scalar(b"c");
        assert_ne!(c1, c2);
    }

    #[test]
    fn length_prefixing_prevents_collision() {
        // ("ab", "cd") vs ("abc", "d") must not collide.
        let mut t1 = Transcript::new(b"x");
        t1.append_bytes(b"m", b"ab");
        t1.append_bytes(b"m", b"cd");
        let c1 = t1.challenge_scalar(b"c");

        let mut t2 = Transcript::new(b"x");
        t2.append_bytes(b"m", b"abc");
        t2.append_bytes(b"m", b"d");
        let c2 = t2.challenge_scalar(b"c");

        assert_ne!(c1, c2);
    }

    #[test]
    fn byte_challenge_is_deterministic_for_equal_transcripts() {
        let mut t1 = Transcript::new(b"x");
        t1.append_bytes(b"m", b"payload");
        let c1: [u8; 32] = t1.challenge_bytes(b"c");

        let mut t2 = Transcript::new(b"x");
        t2.append_bytes(b"m", b"payload");
        let c2: [u8; 32] = t2.challenge_bytes(b"c");

        assert_eq!(c1, c2);
    }
}
