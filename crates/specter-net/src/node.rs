//! Network node — integrates gossip, consensus, and the nullifier set.

use crate::consensus::ConsensusState;
use crate::gossip::GossipProtocol;
use crate::protocol::NodeId;

/// A Specter network node combining gossip and consensus.
pub struct NetworkNode {
    pub id: NodeId,
    pub gossip: GossipProtocol,
    pub consensus: ConsensusState,
}

impl NetworkNode {
    /// Create a new network node.
    pub fn new(id: NodeId, peers: Vec<NodeId>, validators: Vec<NodeId>) -> Self {
        Self {
            id,
            gossip: GossipProtocol::new(id, peers),
            consensus: ConsensusState::new(id, validators),
        }
    }

    /// Submit a nullifier (from a local transfer) — gossips + submits to consensus.
    pub fn submit_nullifier(&mut self, nullifier: [u8; 32]) {
        self.gossip.broadcast_nullifier(nullifier);
        self.consensus.submit_nullifier(nullifier);
    }

    /// Check if a nullifier is known (either in gossip or committed).
    pub fn is_nullifier_known(&self, nullifier: &[u8; 32]) -> bool {
        self.gossip.has_nullifier(nullifier) || self.consensus.is_committed(nullifier)
    }

    /// Get stats about this node.
    pub fn stats(&self) -> NodeStats {
        NodeStats {
            id: self.id,
            gossip_nullifiers: self.gossip.known_nullifiers(),
            committed_nullifiers: self.consensus.nullifier_count(),
            committed_blocks: self.consensus.block_count(),
            current_height: self.consensus.current_height,
            is_leader: self.consensus.current_leader() == self.id,
        }
    }
}

/// Statistics about a network node.
#[derive(Debug)]
pub struct NodeStats {
    pub id: NodeId,
    pub gossip_nullifiers: usize,
    pub committed_nullifiers: usize,
    pub committed_blocks: usize,
    pub current_height: u64,
    pub is_leader: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_creation() {
        let node = NetworkNode::new(1, vec![2, 3], vec![1, 2, 3]);
        assert_eq!(node.id, 1);
        let stats = node.stats();
        assert_eq!(stats.gossip_nullifiers, 0);
        assert_eq!(stats.committed_nullifiers, 0);
    }

    #[test]
    fn test_submit_nullifier() {
        let mut node = NetworkNode::new(1, vec![2, 3], vec![1, 2, 3]);
        node.submit_nullifier([42u8; 32]);
        assert!(node.is_nullifier_known(&[42u8; 32]));
        assert!(!node.is_nullifier_known(&[99u8; 32]));
    }

    #[test]
    fn test_network_simulation() {
        let validators = vec![1, 2, 3];

        let mut node1 = NetworkNode::new(1, vec![2, 3], validators.clone());
        let mut node2 = NetworkNode::new(2, vec![1, 3], validators.clone());
        let mut node3 = NetworkNode::new(3, vec![1, 2], validators.clone());

        // Node 1 submits a nullifier
        node1.submit_nullifier([42u8; 32]);

        // Gossip propagation
        let msgs_to_2 = node1.gossip.drain_messages_for(2);
        for msg in msgs_to_2 {
            if let crate::protocol::Message::NullifierBroadcast { nullifier, sender } = msg {
                node2.gossip.handle_nullifier_broadcast(nullifier, sender);
                node2.consensus.submit_nullifier(nullifier);
            }
        }
        let msgs_to_3 = node1.gossip.drain_messages_for(3);
        for msg in msgs_to_3 {
            if let crate::protocol::Message::NullifierBroadcast { nullifier, sender } = msg {
                node3.gossip.handle_nullifier_broadcast(nullifier, sender);
                node3.consensus.submit_nullifier(nullifier);
            }
        }

        // All nodes know the nullifier via gossip
        assert!(node1.is_nullifier_known(&[42u8; 32]));
        assert!(node2.is_nullifier_known(&[42u8; 32]));
        assert!(node3.is_nullifier_known(&[42u8; 32]));

        // Consensus: node 1 is leader, proposes block
        let block = node1.consensus.propose_block().unwrap();

        // All vote
        let v1 = node1.consensus.vote_on_block(&block);
        let v2 = node2.consensus.vote_on_block(&block);
        let v3 = node3.consensus.vote_on_block(&block);

        // Collect at node 1
        node1.consensus.receive_vote(v2);
        node1.consensus.receive_vote(v3);

        // Commit
        assert!(node1.consensus.try_commit(&block).unwrap());
        assert!(node1.consensus.is_committed(&[42u8; 32]));
        assert_eq!(node1.consensus.block_count(), 1);
    }
}
