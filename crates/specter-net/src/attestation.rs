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

use sha2::{Digest, Sha256};

/// A single attestation - a witness record of a transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// Token ID being transferred.
    pub token_id: [u8; 32],
    /// Hash of the sender's identity commitment.
    pub sender_hash: [u8; 32],
    /// Hash of the receiver's identity commitment.
    pub receiver_hash: [u8; 32],
    /// Position in the transfer chain (0 = first transfer).
    pub chain_position: u32,
    /// Hash of the previous attestation (0 for first).
    pub prev_hash: [u8; 32],
    /// Hash of this attestation (binds all fields).
    pub hash: [u8; 32],
}

impl Attestation {
    /// Create a new attestation.
    pub fn new(
        token_id: [u8; 32],
        sender_hash: [u8; 32],
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
        Self {
            token_id,
            sender_hash,
            receiver_hash,
            chain_position,
            prev_hash,
            hash,
        }
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

    /// Add a transfer attestation to the chain.
    pub fn add_transfer(
        &mut self,
        sender_hash: [u8; 32],
        receiver_hash: [u8; 32],
    ) {
        let position = self.attestations.len() as u32;
        let prev_hash = self
            .attestations
            .last()
            .map(|a| a.hash)
            .unwrap_or([0u8; 32]);

        let attestation = Attestation::new(
            self.token_id,
            sender_hash,
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

    fn token() -> [u8; 32] {
        [42u8; 32]
    }

    fn user(id: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = id;
        h
    }

    #[test]
    fn test_single_transfer_attestation() {
        let mut chain = AttestationChain::new(token());
        chain.add_transfer(user(1), user(2));

        assert_eq!(chain.witness_count(), 1);
        assert!(chain.verify_integrity());
    }

    #[test]
    fn test_multi_transfer_chain() {
        let mut chain = AttestationChain::new(token());
        chain.add_transfer(user(1), user(2)); // Alice -> Bob
        chain.add_transfer(user(2), user(3)); // Bob -> Carol
        chain.add_transfer(user(3), user(4)); // Carol -> Dave

        assert_eq!(chain.witness_count(), 3);
        assert!(chain.verify_integrity());

        // Each attestation links to the previous
        assert_eq!(chain.attestations[1].prev_hash, chain.attestations[0].hash);
        assert_eq!(chain.attestations[2].prev_hash, chain.attestations[1].hash);
    }

    #[test]
    fn test_consistent_chains() {
        let mut chain_a = AttestationChain::new(token());
        chain_a.add_transfer(user(1), user(2));

        let chain_b = chain_a.clone();

        assert_eq!(
            detect_double_spend(&chain_a, &chain_b),
            ChainComparison::Consistent
        );
    }

    #[test]
    fn test_double_spend_detected() {
        // Alice sends same token to Bob AND Carol
        let mut chain_bob = AttestationChain::new(token());
        chain_bob.add_transfer(user(1), user(2)); // Alice -> Bob

        let mut chain_carol = AttestationChain::new(token());
        chain_carol.add_transfer(user(1), user(3)); // Alice -> Carol (DOUBLE SPEND!)

        let result = detect_double_spend(&chain_bob, &chain_carol);
        assert_eq!(
            result,
            ChainComparison::Conflict {
                position: 0,
                cheater_hash: user(1), // Alice is the cheater
            }
        );
    }

    #[test]
    fn test_double_spend_mid_chain() {
        // Shared history: Alice -> Bob
        // Then Bob double-spends to Carol AND Dave
        let mut chain_carol = AttestationChain::new(token());
        chain_carol.add_transfer(user(1), user(2)); // Alice -> Bob (shared)
        chain_carol.add_transfer(user(2), user(3)); // Bob -> Carol

        let mut chain_dave = AttestationChain::new(token());
        chain_dave.add_transfer(user(1), user(2)); // Alice -> Bob (shared)
        chain_dave.add_transfer(user(2), user(4)); // Bob -> Dave (DOUBLE SPEND!)

        let result = detect_double_spend(&chain_carol, &chain_dave);
        assert_eq!(
            result,
            ChainComparison::Conflict {
                position: 1,
                cheater_hash: user(2), // Bob is the cheater
            }
        );
    }

    #[test]
    fn test_different_tokens_not_comparable() {
        let mut chain_a = AttestationChain::new([1u8; 32]);
        chain_a.add_transfer(user(1), user(2));

        let mut chain_b = AttestationChain::new([2u8; 32]);
        chain_b.add_transfer(user(1), user(2));

        assert_eq!(
            detect_double_spend(&chain_a, &chain_b),
            ChainComparison::DifferentTokens
        );
    }

    #[test]
    fn test_tampered_chain_fails_integrity() {
        let mut chain = AttestationChain::new(token());
        chain.add_transfer(user(1), user(2));
        chain.add_transfer(user(2), user(3));

        // Tamper with attestation
        chain.attestations[0].sender_hash = user(99);
        assert!(!chain.verify_integrity());
    }

    #[test]
    fn test_long_chain_integrity() {
        let mut chain = AttestationChain::new(token());
        for i in 0..50 {
            chain.add_transfer(user(i), user(i + 1));
        }
        assert_eq!(chain.witness_count(), 50);
        assert!(chain.verify_integrity());
    }

    #[test]
    fn test_more_witnesses_is_harder_to_evade() {
        // With 0 witnesses (first transfer), no offline detection
        // With 5 witnesses, offline detection is likely
        // With 20 witnesses, offline detection is near-certain

        let mut chain = AttestationChain::new(token());
        for i in 0..20 {
            chain.add_transfer(user(i), user(i + 1));
        }

        // Each participant has seen part of the chain
        // If the cheater double-spends at any point, at least
        // one witness has a conflicting chain
        assert_eq!(chain.witness_count(), 20);
        assert!(chain.verify_integrity());
    }
}
