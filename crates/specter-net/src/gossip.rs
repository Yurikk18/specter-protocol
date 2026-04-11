//! Gossip protocol for nullifier propagation with authenticated messages.
//!
//! Every nullifier broadcast is Schnorr-signed by the sender.
//! Receiving nodes verify the signature against the sender's registered
//! public key before accepting. This prevents injection of forged
//! nullifiers that could cause DoS by poisoning the nullifier set.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::protocol::{Message, NodeId};

/// Errors for gossip operations.
#[derive(Debug, thiserror::Error)]
pub enum GossipError {
    #[error("unknown sender: {0}")]
    UnknownSender(NodeId),

    #[error("invalid signature from sender: {0}")]
    InvalidSignature(NodeId),

    #[error("nullifier set at capacity")]
    AtCapacity,
}

/// Maximum outbound messages queued per peer before rejecting.
const MAX_OUTBOX_PER_PEER: usize = 10_000;

/// Maximum known nullifiers before oldest are evicted.
const MAX_KNOWN_NULLIFIERS: usize = 1_000_000;

/// Sign a nullifier broadcast message with a Schnorr signature.
///
/// Returns (R_compressed, s_bytes) for inclusion in the broadcast.
pub fn sign_nullifier_broadcast(
    nullifier: &[u8; 32],
    sender: NodeId,
    secret_key: &Scalar,
    public_key: &RistrettoPoint,
) -> ([u8; 32], [u8; 32]) {
    let k = specter_primitives::scalar_utils::random_scalar();
    let r = k * G;
    let e = nullifier_sig_challenge(&r, public_key, nullifier, sender);
    let s = k + e * secret_key;

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(r.compress().as_bytes());
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(s.as_bytes());
    (r_bytes, s_bytes)
}

/// Verify a nullifier broadcast signature.
pub fn verify_nullifier_broadcast(
    nullifier: &[u8; 32],
    sender: NodeId,
    signature_r: &[u8; 32],
    signature_s: &[u8; 32],
    public_key: &RistrettoPoint,
) -> bool {
    // Decompress R
    let r = match curve25519_dalek::ristretto::CompressedRistretto::from_slice(signature_r) {
        Ok(compressed) => match compressed.decompress() {
            Some(point) => point,
            None => return false,
        },
        Err(_) => return false,
    };

    // Reconstruct s scalar (canonical check via from_bytes_mod_order + comparison)
    let mut s_arr = [0u8; 32];
    s_arr.copy_from_slice(signature_s);
    let s = Scalar::from_bytes_mod_order(s_arr);
    // Reject non-canonical: if from_bytes_mod_order changed the bytes, it was non-canonical
    if s.as_bytes() != &s_arr {
        return false;
    }

    let e = nullifier_sig_challenge(&r, public_key, nullifier, sender);
    let lhs = s * G;
    let rhs = r + e * public_key;
    // RistrettoPoint PartialEq in dalek 4.x delegates to ConstantTimeEq
    lhs == rhs
}

/// Hash function for nullifier broadcast challenge.
fn nullifier_sig_challenge(
    r: &RistrettoPoint,
    pk: &RistrettoPoint,
    nullifier: &[u8; 32],
    sender: NodeId,
) -> Scalar {
    let hash = Sha512::new()
        .chain_update(b"specter-gossip-sig:")
        .chain_update(r.compress().as_bytes())
        .chain_update(pk.compress().as_bytes())
        .chain_update(nullifier)
        .chain_update(sender.to_le_bytes())
        .finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// A gossip layer that propagates authenticated nullifiers across the network.
pub struct GossipProtocol {
    /// This node's ID.
    pub node_id: NodeId,
    /// Known nullifiers (already seen).
    seen_nullifiers: HashSet<[u8; 32]>,
    /// Connected peer IDs.
    peers: Vec<NodeId>,
    /// Outbound message queue (peer_id -> messages to send).
    outbox: HashMap<NodeId, VecDeque<Message>>,
}

impl GossipProtocol {
    /// Create a new gossip protocol instance for a node.
    pub fn new(node_id: NodeId, peers: Vec<NodeId>) -> Self {
        let outbox = peers.iter().map(|&p| (p, VecDeque::new())).collect();
        Self {
            node_id,
            seen_nullifiers: HashSet::new(),
            peers,
            outbox,
        }
    }

    /// Broadcast a signed nullifier to all peers.
    ///
    /// The caller must provide a valid Schnorr signature over the nullifier.
    /// Returns true if the nullifier was new (first time seen).
    pub fn broadcast_nullifier_signed(
        &mut self,
        nullifier: [u8; 32],
        signature_r: [u8; 32],
        signature_s: [u8; 32],
    ) -> bool {
        if self.seen_nullifiers.len() >= MAX_KNOWN_NULLIFIERS {
            return false;
        }
        if !self.seen_nullifiers.insert(nullifier) {
            return false;
        }

        let msg = Message::NullifierBroadcast {
            nullifier,
            sender: self.node_id,
            signature_r,
            signature_s,
        };
        for peer_id in &self.peers {
            if let Some(queue) = self.outbox.get_mut(peer_id) {
                if queue.len() >= MAX_OUTBOX_PER_PEER {
                    continue;
                }
                queue.push_back(msg.clone());
            }
        }
        true
    }

    /// Convenience: broadcast without signature — **TEST-ONLY**.
    ///
    /// Fills signature fields with zeros. A peer calling `handle_verified_broadcast`
    /// will reject this message because a zero signature doesn't verify; only the
    /// legacy `handle_nullifier_broadcast` accepts it. Marked `#[cfg(test)]` so
    /// production code cannot accidentally emit unauthenticated gossip.
    #[cfg(test)]
    pub fn broadcast_nullifier(&mut self, nullifier: [u8; 32]) -> bool {
        self.broadcast_nullifier_signed(nullifier, [0u8; 32], [0u8; 32])
    }

    /// Handle a received nullifier broadcast with signature verification.
    ///
    /// Verifies the sender's Schnorr signature before accepting.
    /// If valid and new, re-broadcasts to other peers (excluding the sender).
    pub fn handle_verified_broadcast(
        &mut self,
        nullifier: [u8; 32],
        from: NodeId,
        signature_r: &[u8; 32],
        signature_s: &[u8; 32],
        validator_keys: &HashMap<NodeId, RistrettoPoint>,
    ) -> Result<bool, GossipError> {
        // Verify sender is a known validator
        let pubkey = validator_keys
            .get(&from)
            .ok_or(GossipError::UnknownSender(from))?;

        // Verify Schnorr signature
        if !verify_nullifier_broadcast(&nullifier, from, signature_r, signature_s, pubkey) {
            return Err(GossipError::InvalidSignature(from));
        }

        if self.seen_nullifiers.len() >= MAX_KNOWN_NULLIFIERS {
            return Err(GossipError::AtCapacity);
        }
        if !self.seen_nullifiers.insert(nullifier) {
            return Ok(false); // already known
        }

        // Re-broadcast to peers except the sender
        let msg = Message::NullifierBroadcast {
            nullifier,
            sender: self.node_id,
            signature_r: *signature_r,
            signature_s: *signature_s,
        };
        for peer_id in &self.peers {
            if *peer_id != from {
                if let Some(queue) = self.outbox.get_mut(peer_id) {
                    if queue.len() >= MAX_OUTBOX_PER_PEER {
                        continue;
                    }
                    queue.push_back(msg.clone());
                }
            }
        }
        Ok(true)
    }

    /// Handle a received nullifier broadcast — **TEST-ONLY** (no signature verification).
    ///
    /// DEPRECATED for production: use `handle_verified_broadcast`. Marked
    /// `#[cfg(test)]` so releases cannot accidentally accept unsigned gossip
    /// which would let an arbitrary network peer poison the nullifier set.
    #[cfg(test)]
    pub fn handle_nullifier_broadcast(&mut self, nullifier: [u8; 32], from: NodeId) -> bool {
        if self.seen_nullifiers.len() >= MAX_KNOWN_NULLIFIERS {
            return false;
        }
        if !self.seen_nullifiers.insert(nullifier) {
            return false;
        }

        let msg = Message::NullifierBroadcast {
            nullifier,
            sender: self.node_id,
            signature_r: [0u8; 32],
            signature_s: [0u8; 32],
        };
        for peer_id in &self.peers {
            if *peer_id != from {
                if let Some(queue) = self.outbox.get_mut(peer_id) {
                    if queue.len() >= MAX_OUTBOX_PER_PEER {
                        continue;
                    }
                    queue.push_back(msg.clone());
                }
            }
        }
        true
    }

    /// Drain outbound messages for a specific peer.
    pub fn drain_messages_for(&mut self, peer_id: NodeId) -> Vec<Message> {
        self.outbox
            .get_mut(&peer_id)
            .map(|q| q.drain(..).collect())
            .unwrap_or_default()
    }

    /// Number of known nullifiers.
    pub fn known_nullifiers(&self) -> usize {
        self.seen_nullifiers.len()
    }

    /// Check if a nullifier is known.
    pub fn has_nullifier(&self, nullifier: &[u8; 32]) -> bool {
        self.seen_nullifiers.contains(nullifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcast_new_nullifier() {
        let mut gossip = GossipProtocol::new(1, vec![2, 3, 4]);
        let nullifier = [42u8; 32];

        assert!(gossip.broadcast_nullifier(nullifier));
        assert_eq!(gossip.known_nullifiers(), 1);

        assert_eq!(gossip.drain_messages_for(2).len(), 1);
        assert_eq!(gossip.drain_messages_for(3).len(), 1);
        assert_eq!(gossip.drain_messages_for(4).len(), 1);
    }

    #[test]
    fn test_duplicate_broadcast_ignored() {
        let mut gossip = GossipProtocol::new(1, vec![2, 3]);
        let nullifier = [42u8; 32];

        assert!(gossip.broadcast_nullifier(nullifier));
        assert!(!gossip.broadcast_nullifier(nullifier));
        assert_eq!(gossip.known_nullifiers(), 1);
    }

    #[test]
    fn test_handle_received_rebroadcasts() {
        let mut gossip = GossipProtocol::new(1, vec![2, 3, 4]);
        let nullifier = [42u8; 32];

        assert!(gossip.handle_nullifier_broadcast(nullifier, 2));
        assert_eq!(gossip.known_nullifiers(), 1);

        assert_eq!(gossip.drain_messages_for(2).len(), 0);
        assert_eq!(gossip.drain_messages_for(3).len(), 1);
        assert_eq!(gossip.drain_messages_for(4).len(), 1);
    }

    #[test]
    fn test_signed_broadcast_and_verified_receive() {
        let sk = specter_primitives::scalar_utils::random_scalar();
        let pk = sk * G;

        let nullifier = [42u8; 32];
        let sender: NodeId = 1;

        // Sign the broadcast
        let (sig_r, sig_s) = sign_nullifier_broadcast(&nullifier, sender, &sk, &pk);

        // Verify the broadcast
        assert!(verify_nullifier_broadcast(&nullifier, sender, &sig_r, &sig_s, &pk));

        // Wrong nullifier should fail
        let mut bad_null = nullifier;
        bad_null[0] ^= 0xFF;
        assert!(!verify_nullifier_broadcast(&bad_null, sender, &sig_r, &sig_s, &pk));

        // Wrong sender ID should fail
        assert!(!verify_nullifier_broadcast(&nullifier, 99, &sig_r, &sig_s, &pk));

        // Wrong public key should fail
        let other_sk = specter_primitives::scalar_utils::random_scalar();
        let other_pk = other_sk * G;
        assert!(!verify_nullifier_broadcast(&nullifier, sender, &sig_r, &sig_s, &other_pk));
    }

    #[test]
    fn test_verified_broadcast_rejects_forged() {
        let sk = specter_primitives::scalar_utils::random_scalar();
        let pk = sk * G;
        let mut keys = HashMap::new();
        keys.insert(1u64, pk);

        let mut gossip = GossipProtocol::new(2, vec![1, 3]);
        let nullifier = [42u8; 32];

        // Forged signature (random bytes)
        let forged_r = [0xFFu8; 32];
        let forged_s = [0x01u8; 32];

        let result = gossip.handle_verified_broadcast(nullifier, 1, &forged_r, &forged_s, &keys);
        assert!(result.is_err());
    }

    #[test]
    fn test_verified_broadcast_accepts_valid() {
        let sk = specter_primitives::scalar_utils::random_scalar();
        let pk = sk * G;
        let mut keys = HashMap::new();
        keys.insert(1u64, pk);

        let mut gossip = GossipProtocol::new(2, vec![1, 3]);
        let nullifier = [42u8; 32];

        let (sig_r, sig_s) = sign_nullifier_broadcast(&nullifier, 1, &sk, &pk);
        let result = gossip.handle_verified_broadcast(nullifier, 1, &sig_r, &sig_s, &keys);
        assert!(result.unwrap());
        assert!(gossip.has_nullifier(&nullifier));
    }

    #[test]
    fn test_verified_broadcast_rejects_unknown_sender() {
        let keys: HashMap<NodeId, RistrettoPoint> = HashMap::new();
        let mut gossip = GossipProtocol::new(2, vec![1]);
        let result = gossip.handle_verified_broadcast([42u8; 32], 99, &[0; 32], &[0; 32], &keys);
        assert!(matches!(result, Err(GossipError::UnknownSender(99))));
    }

    #[test]
    fn test_gossip_network_simulation() {
        let mut node1 = GossipProtocol::new(1, vec![2, 3]);
        let mut node2 = GossipProtocol::new(2, vec![1, 3, 4]);
        let mut node3 = GossipProtocol::new(3, vec![1, 2, 4]);
        let mut node4 = GossipProtocol::new(4, vec![2, 3]);

        let nullifier = [99u8; 32];
        node1.broadcast_nullifier(nullifier);

        for msg in node1.drain_messages_for(2) {
            if let Message::NullifierBroadcast { nullifier, sender, .. } = msg {
                node2.handle_nullifier_broadcast(nullifier, sender);
            }
        }
        for msg in node1.drain_messages_for(3) {
            if let Message::NullifierBroadcast { nullifier, sender, .. } = msg {
                node3.handle_nullifier_broadcast(nullifier, sender);
            }
        }

        for msg in node2.drain_messages_for(4) {
            if let Message::NullifierBroadcast { nullifier, sender, .. } = msg {
                node4.handle_nullifier_broadcast(nullifier, sender);
            }
        }

        assert!(node1.has_nullifier(&nullifier));
        assert!(node2.has_nullifier(&nullifier));
        assert!(node3.has_nullifier(&nullifier));
        assert!(node4.has_nullifier(&nullifier));
    }
}
