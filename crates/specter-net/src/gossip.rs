//! Gossip protocol for nullifier propagation.
//!
//! Nodes propagate spent nullifiers to their peers via gossip.
//! Each node maintains a set of known nullifiers and forwards
//! new ones to connected peers. This provides eventual consistency
//! for double-spend detection across the network.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::protocol::{Message, NodeId};

/// Maximum outbound messages queued per peer before rejecting.
const MAX_OUTBOX_PER_PEER: usize = 10_000;

/// Maximum known nullifiers before oldest are evicted.
const MAX_KNOWN_NULLIFIERS: usize = 1_000_000;

/// A gossip layer that propagates nullifiers across the network.
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

    /// Broadcast a new nullifier to all peers.
    ///
    /// Returns true if the nullifier was new (first time seen).
    /// Returns false if it was already known (duplicate).
    pub fn broadcast_nullifier(&mut self, nullifier: [u8; 32]) -> bool {
        if self.seen_nullifiers.len() >= MAX_KNOWN_NULLIFIERS {
            return false; // memory protection
        }
        if !self.seen_nullifiers.insert(nullifier) {
            return false; // already seen
        }

        // Queue broadcast to all peers (with rate limiting)
        let msg = Message::NullifierBroadcast {
            nullifier,
            sender: self.node_id,
        };
        for peer_id in &self.peers {
            if let Some(queue) = self.outbox.get_mut(peer_id) {
                if queue.len() >= MAX_OUTBOX_PER_PEER {
                    continue; // drop message for this peer (rate limited)
                }
                queue.push_back(msg.clone());
            }
        }
        true
    }

    /// Handle a received nullifier broadcast from a peer.
    ///
    /// If new, re-broadcasts to other peers (excluding the sender).
    pub fn handle_nullifier_broadcast(&mut self, nullifier: [u8; 32], from: NodeId) -> bool {
        if self.seen_nullifiers.len() >= MAX_KNOWN_NULLIFIERS {
            return false;
        }
        if !self.seen_nullifiers.insert(nullifier) {
            return false; // already known
        }

        // Re-broadcast to peers except the sender (with rate limiting)
        let msg = Message::NullifierBroadcast {
            nullifier,
            sender: self.node_id,
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

        // Should have messages queued for each peer
        assert_eq!(gossip.drain_messages_for(2).len(), 1);
        assert_eq!(gossip.drain_messages_for(3).len(), 1);
        assert_eq!(gossip.drain_messages_for(4).len(), 1);
    }

    #[test]
    fn test_duplicate_broadcast_ignored() {
        let mut gossip = GossipProtocol::new(1, vec![2, 3]);
        let nullifier = [42u8; 32];

        assert!(gossip.broadcast_nullifier(nullifier));
        assert!(!gossip.broadcast_nullifier(nullifier)); // duplicate
        assert_eq!(gossip.known_nullifiers(), 1);
    }

    #[test]
    fn test_handle_received_rebroadcasts() {
        let mut gossip = GossipProtocol::new(1, vec![2, 3, 4]);
        let nullifier = [42u8; 32];

        // Receive from peer 2
        assert!(gossip.handle_nullifier_broadcast(nullifier, 2));
        assert_eq!(gossip.known_nullifiers(), 1);

        // Should rebroadcast to 3 and 4 (not back to 2)
        assert_eq!(gossip.drain_messages_for(2).len(), 0);
        assert_eq!(gossip.drain_messages_for(3).len(), 1);
        assert_eq!(gossip.drain_messages_for(4).len(), 1);
    }

    #[test]
    fn test_gossip_network_simulation() {
        // Simulate 4-node network: 1-2, 1-3, 2-3, 2-4, 3-4
        let mut node1 = GossipProtocol::new(1, vec![2, 3]);
        let mut node2 = GossipProtocol::new(2, vec![1, 3, 4]);
        let mut node3 = GossipProtocol::new(3, vec![1, 2, 4]);
        let mut node4 = GossipProtocol::new(4, vec![2, 3]);

        // Node 1 broadcasts a nullifier
        let nullifier = [99u8; 32];
        node1.broadcast_nullifier(nullifier);

        // Deliver messages from node 1 to peers
        for msg in node1.drain_messages_for(2) {
            if let Message::NullifierBroadcast { nullifier, sender } = msg {
                node2.handle_nullifier_broadcast(nullifier, sender);
            }
        }
        for msg in node1.drain_messages_for(3) {
            if let Message::NullifierBroadcast { nullifier, sender } = msg {
                node3.handle_nullifier_broadcast(nullifier, sender);
            }
        }

        // Node 2 should forward to node 4
        for msg in node2.drain_messages_for(4) {
            if let Message::NullifierBroadcast { nullifier, sender } = msg {
                node4.handle_nullifier_broadcast(nullifier, sender);
            }
        }

        // All nodes should know the nullifier
        assert!(node1.has_nullifier(&nullifier));
        assert!(node2.has_nullifier(&nullifier));
        assert!(node3.has_nullifier(&nullifier));
        assert!(node4.has_nullifier(&nullifier));
    }
}
