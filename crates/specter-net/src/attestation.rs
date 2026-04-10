//! Social Attestation Chain for offline double-spend detection.
//!
//! When Alice transfers a token to Bob offline, Bob becomes a "witness"
//! to that transfer. When Bob later transfers to Carol, Carol sees the
//! chain: Alice -> Bob -> Carol. If Alice double-spends the same token
//! to Dave, the chain Alice -> Dave conflicts with Alice -> Bob -> Carol.
//!
//! When any two devices with conflicting chains meet (BLE, NFC, WiFi),
//! the double-spend is detected OFFLINE - before anyone goes online.
//!
//! The more transfers a token has, the MORE witnesses exist, and the
//! HARDER double-spend becomes. This is the opposite of traditional
//! systems where more transfers = more risk.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha256, Sha512};

/// Schnorr signature on an attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationSig {
    pub r: RistrettoPoint,
    pub s: Scalar,
}

/// A single attestation - a witness record of a transfer.
/// Now includes a Schnorr signature from the sender proving authenticity.
#[derive(Clone, Debug)]
pub struct Attestation {
    /// Token ID being transferred.
    pub token_id: [u8; 32],
    /// Hash of the sender's identity commitment.
    pub sender_hash: [u8; 32],
    /// Sender's public key (for signature verification).
    pub sender_pubkey: RistrettoPoint,
    /// Hash of the receiver's identity commitment.
    pub receiver_hash: [u8; 32],
    /// Position in the transfer chain (0 = first transfer).
    pub chain_position: u32,
    /// Hash of the previous attestation (0 for first).
    pub prev_hash: [u8; 32],
    /// Hash of this attestation (binds all fields).
    pub hash: [u8; 32],
    /// Schnorr signature from the sender proving they authorized this transfer.
    pub signature: AttestationSig,
}

impl Attestation {
    /// Create a new signed attestation.
    /// The sender signs the attestation hash with their secret key.
    pub fn new_signed(
        token_id: [u8; 32],
        sender_hash: [u8; 32],
        sender_secret: &Scalar,
        sender_pubkey: RistrettoPoint,
        receiver_hash: [u8; 32],
        chain_position: u32,
        prev_hash: [u8; 32],
    ) -> Self {
        let hash = Self::compute_hash(
            &token_id,
            &sender_hash,
            &receiver_hash,
            chain_position,
            &prev_hash,
        );
        // Sign the hash with sender's secret key
        let k = specter_primitives::scalar_utils::random_scalar();
        let r = k * G;
        let challenge = Self::sig_challenge(&r, &sender_pubkey, &hash);
        let s = k + challenge * sender_secret;

        Self {
            token_id,
            sender_hash,
            sender_pubkey,
            receiver_hash,
            chain_position,
            prev_hash,
            hash,
            signature: AttestationSig { r, s },
        }
    }

    /// Verify the sender's Schnorr signature on this attestation.
    pub fn verify_signature(&self) -> bool {
        let challenge = Self::sig_challenge(&self.signature.r, &self.sender_pubkey, &self.hash);
        let lhs = self.signature.s * G;
        let rhs = self.signature.r + challenge * self.sender_pubkey;
        lhs == rhs
    }

    fn sig_challenge(r: &RistrettoPoint, pk: &RistrettoPoint, msg: &[u8; 32]) -> Scalar {
        let hash = Sha512::new()
            .chain_update(b"specter-attestation-sig:")
            .chain_update(r.compress().as_bytes())
            .chain_update(pk.compress().as_bytes())
            .chain_update(msg)
            .finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    fn compute_hash(
        token_id: &[u8; 32],
        sender: &[u8; 32],
        receiver: &[u8; 32],
        position: u32,
        prev: &[u8; 32],
    ) -> [u8; 32] {
        let digest = Sha256::new()
            .chain_update(b"specter-attestation:")
            .chain_update(token_id)
            .chain_update(sender)
            .chain_update(receiver)
            .chain_update(position.to_le_bytes())
            .chain_update(prev)
            .finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        hash
    }
}

/// An attestation chain - the full transfer history witnessed by a device.
#[derive(Clone, Debug)]
pub struct AttestationChain {
    /// The token this chain tracks.
    pub token_id: [u8; 32],
    /// Ordered list of attestations.
    pub attestations: Vec<Attestation>,
}

impl AttestationChain {
    /// Create a new empty chain for a token.
    pub fn new(token_id: [u8; 32]) -> Self {
        Self {
            token_id,
            attestations: Vec::new(),
        }
    }

    /// Add a signed transfer attestation to the chain.
    pub fn add_transfer(
        &mut self,
        sender_hash: [u8; 32],
        sender_secret: &Scalar,
        sender_pubkey: RistrettoPoint,
        receiver_hash: [u8; 32],
    ) {
        let position = self.attestations.len() as u32;
        let prev_hash = self
            .attestations
            .last()
            .map(|a| a.hash)
            .unwrap_or([0u8; 32]);

        let attestation = Attestation::new_signed(
            self.token_id,
            sender_hash,
            sender_secret,
            sender_pubkey,
            receiver_hash,
            position,
            prev_hash,
        );
        self.attestations.push(attestation);
    }

    /// Verify the chain integrity (each attestation links to the previous).
    pub fn verify_integrity(&self) -> bool {
        for (i, att) in self.attestations.iter().enumerate() {
            // Check position
            if att.chain_position != i as u32 {
                return false;
            }

            // Check prev_hash linkage
            let expected_prev = if i == 0 {
                [0u8; 32]
            } else {
                self.attestations[i - 1].hash
            };
            if att.prev_hash != expected_prev {
                return false;
            }

            // Check hash correctness
            let expected_hash = Attestation::compute_hash(
                &att.token_id,
                &att.sender_hash,
                &att.receiver_hash,
                att.chain_position,
                &att.prev_hash,
            );
            if att.hash != expected_hash {
                return false;
            }

            // Check token_id consistency
            if att.token_id != self.token_id {
                return false;
            }

            // Verify sender's Schnorr signature
            if !att.verify_signature() {
                return false;
            }
        }
        true
    }

    /// Number of witnesses in the chain.
    pub fn witness_count(&self) -> usize {
        self.attestations.len()
    }
}

/// Result of comparing two attestation chains.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainComparison {
    /// Chains are consistent (same history).
    Consistent,
    /// Chains conflict at a specific position - DOUBLE SPEND DETECTED.
    Conflict {
        /// Position where the chains diverge.
        position: u32,
        /// The sender who double-spent.
        cheater_hash: [u8; 32],
    },
    /// Chains are for different tokens (not comparable).
    DifferentTokens,
}

/// Compare two attestation chains to detect double-spending.
///
/// If two chains for the same token diverge at any position, the sender
/// at that position is the double-spender. The conflicting attestations
/// serve as cryptographic blame proof.
pub fn detect_double_spend(
    chain_a: &AttestationChain,
    chain_b: &AttestationChain,
) -> ChainComparison {
    if chain_a.token_id != chain_b.token_id {
        return ChainComparison::DifferentTokens;
    }

    let min_len = chain_a.attestations.len().min(chain_b.attestations.len());

    for i in 0..min_len {
        let a = &chain_a.attestations[i];
        let b = &chain_b.attestations[i];

        // Same position, same token, but different attestations = conflict
        if a.hash != b.hash {
            // The sender at this position is the cheater
            // (they signed two different transfers at the same chain position)
            return ChainComparison::Conflict {
                position: i as u32,
                cheater_hash: a.sender_hash,
            };
        }
    }

    ChainComparison::Consistent
}

#[cfg(test)]
mod tests {
    use super::*;
    use specter_primitives::scalar_utils::random_scalar;

    fn token() -> [u8; 32] { [42u8; 32] }

    fn user_hash(id: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = id;
        h
    }

    fn keypair() -> (Scalar, RistrettoPoint) {
        let sk = random_scalar();
        let pk = sk * G;
        (sk, pk)
    }

    #[test]
    fn test_signed_attestation_roundtrip() {
        let (sk, pk) = keypair();
        let mut chain = AttestationChain::new(token());
        chain.add_transfer(user_hash(1), &sk, pk, user_hash(2));

        assert_eq!(chain.witness_count(), 1);
        assert!(chain.verify_integrity());
        assert!(chain.attestations[0].verify_signature());
    }

    #[test]
    fn test_multi_transfer_signed() {
        let (sk1, pk1) = keypair();
        let (sk2, pk2) = keypair();
        let (sk3, pk3) = keypair();

        let mut chain = AttestationChain::new(token());
        chain.add_transfer(user_hash(1), &sk1, pk1, user_hash(2));
        chain.add_transfer(user_hash(2), &sk2, pk2, user_hash(3));
        chain.add_transfer(user_hash(3), &sk3, pk3, user_hash(4));

        assert_eq!(chain.witness_count(), 3);
        assert!(chain.verify_integrity());
    }

    #[test]
    fn test_double_spend_detected_signed() {
        let (sk1, pk1) = keypair();

        let mut chain_bob = AttestationChain::new(token());
        chain_bob.add_transfer(user_hash(1), &sk1, pk1, user_hash(2));

        let mut chain_carol = AttestationChain::new(token());
        chain_carol.add_transfer(user_hash(1), &sk1, pk1, user_hash(3));

        match detect_double_spend(&chain_bob, &chain_carol) {
            ChainComparison::Conflict { position, cheater_hash } => {
                assert_eq!(position, 0);
                assert_eq!(cheater_hash, user_hash(1));
            }
            other => panic!("expected Conflict, got {:?}", other),
        }
    }

    #[test]
    fn test_tampered_signature_fails() {
        let (sk, pk) = keypair();
        let mut chain = AttestationChain::new(token());
        chain.add_transfer(user_hash(1), &sk, pk, user_hash(2));

        // Tamper with signature
        chain.attestations[0].signature.s += Scalar::ONE;
        assert!(!chain.verify_integrity());
    }

    #[test]
    fn test_forged_attestation_fails() {
        let (sk, pk) = keypair();
        let (_sk2, pk2) = keypair();

        let mut chain = AttestationChain::new(token());
        chain.add_transfer(user_hash(1), &sk, pk, user_hash(2));

        // Replace sender pubkey with a different key (forged identity)
        chain.attestations[0].sender_pubkey = pk2;
        assert!(!chain.verify_integrity());
    }

    #[test]
    fn test_long_chain_signed() {
        let mut chain = AttestationChain::new(token());
        for i in 0u8..20 {
            let (sk, pk) = keypair();
            chain.add_transfer(user_hash(i), &sk, pk, user_hash(i + 1));
        }
        assert_eq!(chain.witness_count(), 20);
        assert!(chain.verify_integrity());
    }

    #[test]
    fn test_different_tokens() {
        let (sk, pk) = keypair();
        let mut a = AttestationChain::new([1u8; 32]);
        a.add_transfer(user_hash(1), &sk, pk, user_hash(2));
        let mut b = AttestationChain::new([2u8; 32]);
        b.add_transfer(user_hash(1), &sk, pk, user_hash(2));
        assert_eq!(detect_double_spend(&a, &b), ChainComparison::DifferentTokens);
    }
}
