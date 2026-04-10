//! Network node — integrates gossip, consensus, and the nullifier set.

use std::collections::HashMap;

use crate::consensus::{ConsensusState, ValidatorKey, Vote};
use crate::gossip::GossipProtocol;
use crate::protocol::NodeId;

/// A Specter network node combining gossip and consensus.
pub struct NetworkNode {
    pub id: NodeId,
    pub gossip: GossipProtocol,
    pub consensus: ConsensusState,
    pub validator_key: ValidatorKey,
}

impl NetworkNode {
    /// Create a new network node with validator keys.
    pub fn new(
        id: NodeId,
        peers: Vec<NodeId>,
        validator_keys: Vec<ValidatorKey>,
    ) -> Self {
        let validators: Vec<NodeId> = validator_keys.iter().map(|k| k.node_id).collect();
        let pubkeys: HashMap<NodeId, _> = validator_keys.iter()
            .map(|k| (k.node_id, k.public_key))
            .collect();

        let own_key = validator_keys.into_iter()
            .find(|k| k.node_id == id)
            .expect("node must have its own validator key");

        Self {
            id,
            gossip: GossipProtocol::new(id, peers),
            consensus: ConsensusState::new(id, validators, pubkeys)
                .expect("valid consensus params"),
            validator_key: own_key,
        }
    }

    /// Submit a nullifier — gossips + submits to consensus.
    pub fn submit_nullifier(&mut self, nullifier: [u8; 32]) {
        self.gossip.broadcast_nullifier(nullifier);
        self.consensus.submit_nullifier(nullifier);
    }

    /// Check if a nullifier is known.
    pub fn is_nullifier_known(&self, nullifier: &[u8; 32]) -> bool {
        self.gossip.has_nullifier(nullifier) || self.consensus.is_committed(nullifier)
    }

    /// Sign a vote on a block using this node's validator key.
    pub fn sign_vote(&self, block_height: u64, block_hash: &[u8; 32], approve: bool) -> Vote {
        self.validator_key.sign_vote(block_height, block_hash, approve)
    }

    /// Get node stats.
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

    fn make_network() -> (NetworkNode, NetworkNode, NetworkNode) {
        let k1 = ValidatorKey::generate(1);
        let k2 = ValidatorKey::generate(2);
        let k3 = ValidatorKey::generate(3);

        let keys = vec![k1.clone(), k2.clone(), k3.clone()];

        let n1 = NetworkNode::new(1, vec![2, 3], keys.clone());
        let n2 = NetworkNode::new(2, vec![1, 3], keys.clone());
        let n3 = NetworkNode::new(3, vec![1, 2], keys);

        (n1, n2, n3)
    }

    #[test]
    fn test_node_creation() {
        let (node, _, _) = make_network();
        assert_eq!(node.id, 1);
        assert_eq!(node.stats().gossip_nullifiers, 0);
    }

    #[test]
    fn test_submit_nullifier() {
        let (mut node, _, _) = make_network();
        node.submit_nullifier([42u8; 32]);
        assert!(node.is_nullifier_known(&[42u8; 32]));
    }

    #[test]
    fn test_authenticated_consensus_flow() {
        let (mut n1, n2, n3) = make_network();

        n1.submit_nullifier([42u8; 32]);
        let block = n1.consensus.propose_block().unwrap();

        // Each node signs its vote
        let v1 = n1.sign_vote(block.height, &block.hash, true);
        let v2 = n2.sign_vote(block.height, &block.hash, true);
        let v3 = n3.sign_vote(block.height, &block.hash, true);

        // Receive authenticated votes
        n1.consensus.receive_vote(v1).unwrap();
        n1.consensus.receive_vote(v2).unwrap();
        n1.consensus.receive_vote(v3).unwrap();

        assert!(n1.consensus.try_commit(&block).unwrap());
        assert!(n1.consensus.is_committed(&[42u8; 32]));
    }
}
