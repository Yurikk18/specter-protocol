//! Fiat-Shamir transcript for non-interactive proof generation.
//!
//! Provides a sequential hashing transcript that absorbs data and squeezes
//! challenges, used to make interactive protocols non-interactive.

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use curve25519_dalek::Scalar;

/// A Fiat-Shamir transcript built on SHAKE-256.
pub struct Transcript {
    hasher: Shake256,
}

impl Transcript {
    /// Create a new transcript with a domain separator.
    pub fn new(domain: &[u8]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(b"specter-transcript:");
        hasher.update(domain);
        Self { hasher }
    }

    /// Absorb a labeled byte string into the transcript.
    ///
    /// Both label and data are length-prefixed for unambiguous parsing,
    /// preventing cross-field boundary attacks in the Fiat-Shamir hash.
    pub fn absorb(&mut self, label: &[u8], data: &[u8]) {
        self.hasher.update(&(label.len() as u64).to_le_bytes());
        self.hasher.update(label);
        self.hasher.update(&(data.len() as u64).to_le_bytes());
        self.hasher.update(data);
    }

    /// Squeeze a scalar challenge from the transcript.
    pub fn challenge(&mut self, label: &[u8]) -> Scalar {
        self.hasher.update(b"challenge:");
        self.hasher.update(label);
        // Clone the state so we can continue absorbing after squeezing
        let mut reader = self.hasher.clone().finalize_xof();
        let mut wide = [0u8; 64];
        reader.read(&mut wide);
        // Re-absorb the challenge to chain state
        self.hasher.update(&wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    /// Squeeze raw bytes from the transcript.
    pub fn squeeze_bytes(&mut self, label: &[u8], output: &mut [u8]) {
        self.hasher.update(b"squeeze:");
        self.hasher.update(label);
        let mut reader = self.hasher.clone().finalize_xof();
        reader.read(output);
        self.hasher.update(output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_deterministic() {
        let mut t1 = Transcript::new(b"test");
        t1.absorb(b"data", b"hello");
        let c1 = t1.challenge(b"ch");

        let mut t2 = Transcript::new(b"test");
        t2.absorb(b"data", b"hello");
        let c2 = t2.challenge(b"ch");

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_different_data_different_challenge() {
        let mut t1 = Transcript::new(b"test");
        t1.absorb(b"data", b"hello");
        let c1 = t1.challenge(b"ch");

        let mut t2 = Transcript::new(b"test");
        t2.absorb(b"data", b"world");
        let c2 = t2.challenge(b"ch");

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_different_domain_different_challenge() {
        let mut t1 = Transcript::new(b"domain-a");
        t1.absorb(b"data", b"same");
        let c1 = t1.challenge(b"ch");

        let mut t2 = Transcript::new(b"domain-b");
        t2.absorb(b"data", b"same");
        let c2 = t2.challenge(b"ch");

        assert_ne!(c1, c2);
    }
}
