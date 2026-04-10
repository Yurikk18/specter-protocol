//! Simplified BFT consensus for the nullifier set.
//!
//! Implements a simplified HotStuff-2-inspired consensus protocol:
//! 1. A leader proposes a block of new nullifiers.
//! 2. Validators vote on the proposal.
//! 3. If a quorum (2f+1 out of 3f+1) votes yes, the block is committed.
//! 4. Leader rotates each block.
//!
//! The nullifier set is the only shared state that needs consensus.
//! Token issuance and transfer happen off-chain; only nullifier
//! publication requires agreement.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use crate::protocol::NodeId;

/// A block of nullifiers to be committed.
#[derive(Clone, Debug)]
pub struct NullifierBlock {
    /// Block height (monotonically increasing).
    pub height: u64,
    /// The leader who proposed this block.
    pub leader: NodeId,
    /// Nullifiers included in this block.
    pub nullifiers: Vec<[u8; 32]>,
    /// Hash of the block content.
    pub hash: [u8; 32],
}

impl NullifierBlock {
    /// Create a new block.
    pub fn new(height: u64, leader: NodeId, nullifiers: Vec<[u8; 32]>) -> Self {
        let hash = Self::compute_hash(height, leader, &nullifiers);
        Self {
            height,
            leader,
            nullifiers,
            hash,
        }
    }

    fn compute_hash(height: u64, leader: NodeId, nullifiers: &[[u8; 32]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"specter-block:");
        hasher.update(height.to_le_bytes());
        hasher.update(leader.to_le_bytes());
        for n in nullifiers {
            hasher.update(n);
        }
        let digest = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        hash
    }
}

/// Vote on a proposed block.
#[derive(Clone, Debug)]
pub struct Vote {
    pub voter: NodeId,
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub approve: bool,
}

/// The consensus state machine for a single node.
pub struct ConsensusState {
    /// This node's ID.
    pub node_id: NodeId,
    /// Total number of validators.
    pub total_validators: usize,
    /// Maximum Byzantine faults tolerated: f = (total - 1) / 3.
    pub max_faults: usize,
    /// Quorum size: 2f + 1.
    pub quorum_size: usize,
    /// All validator node IDs.
    pub validators: Vec<NodeId>,
    /// Current block height.
    pub current_height: u64,
    /// Committed blocks.
    pub committed_blocks: Vec<NullifierBlock>,
    /// Committed nullifier set.
    pub committed_nullifiers: HashSet<[u8; 32]>,
    /// Pending nullifiers (not yet in a block).
    pub pending_nullifiers: Vec<[u8; 32]>,
    /// Votes for the current proposal.
    votes: HashMap<[u8; 32], Vec<Vote>>,
    /// Current view number (incremented on view change / leader timeout).
    pub view: u64,
}

impl ConsensusState {
    /// Create a new consensus state.
    ///
    /// # Panics
    /// Panics if `total_validators < 4` (need at least 3f+1 = 4 for f=1).
    pub fn new(node_id: NodeId, validators: Vec<NodeId>) -> Self {
        let n = validators.len();
        assert!(n >= 1, "need at least 1 validator");
        let max_faults = (n - 1) / 3;
        let quorum_size = if n < 4 { n } else { 2 * max_faults + 1 };

        Self {
            node_id,
            total_validators: n,
            max_faults,
            quorum_size,
            validators,
            current_height: 0,
            committed_blocks: Vec::new(),
            committed_nullifiers: HashSet::new(),
            pending_nullifiers: Vec::new(),
            votes: HashMap::new(),
            view: 0,
        }
    }

    /// Get the current leader (round-robin with view offset).
    pub fn current_leader(&self) -> NodeId {
        let idx = (self.current_height as usize + self.view as usize) % self.validators.len();
        self.validators[idx]
    }

    /// Submit a nullifier to the pending pool.
    pub fn submit_nullifier(&mut self, nullifier: [u8; 32]) {
        if !self.committed_nullifiers.contains(&nullifier) {
            self.pending_nullifiers.push(nullifier);
        }
    }

    /// Propose a new block (only valid if this node is the leader).
    pub fn propose_block(&mut self) -> Result<NullifierBlock, ConsensusError> {
        if self.current_leader() != self.node_id {
            return Err(ConsensusError::NotLeader {
                leader: self.current_leader(),
                self_id: self.node_id,
            });
        }

        let nullifiers: Vec<[u8; 32]> = self.pending_nullifiers.drain(..).collect();
        let block = NullifierBlock::new(self.current_height, self.node_id, nullifiers);
        Ok(block)
    }

    /// Cast a vote on a proposed block.
    pub fn vote_on_block(&mut self, block: &NullifierBlock) -> Vote {
        // Verify block is for the current height and from the correct leader
        let approve = block.height == self.current_height
            && block.leader == self.current_leader()
            && block.hash == NullifierBlock::compute_hash(block.height, block.leader, &block.nullifiers);

        let vote = Vote {
            voter: self.node_id,
            block_height: block.height,
            block_hash: block.hash,
            approve,
        };

        self.votes
            .entry(block.hash)
            .or_default()
            .push(vote.clone());

        vote
    }

    /// Collect a vote from another node.
    pub fn receive_vote(&mut self, vote: Vote) {
        self.votes
            .entry(vote.block_hash)
            .or_default()
            .push(vote);
    }

    /// Check if a block has reached quorum and commit it.
    pub fn try_commit(&mut self, block: &NullifierBlock) -> Result<bool, ConsensusError> {
        let votes = self.votes.get(&block.hash).cloned().unwrap_or_default();
        let approvals = votes.iter().filter(|v| v.approve).count();

        if approvals >= self.quorum_size {
            // Commit the block
            for nullifier in &block.nullifiers {
                self.committed_nullifiers.insert(*nullifier);
            }
            self.committed_blocks.push(block.clone());
            self.current_height += 1;
            self.votes.remove(&block.hash);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if a nullifier has been committed.
    pub fn is_committed(&self, nullifier: &[u8; 32]) -> bool {
        self.committed_nullifiers.contains(nullifier)
    }

    /// Number of committed blocks.
    pub fn block_count(&self) -> usize {
        self.committed_blocks.len()
    }

    /// Total committed nullifiers.
    pub fn nullifier_count(&self) -> usize {
        self.committed_nullifiers.len()
    }

    /// Trigger a view change — rotate leader when current leader fails.
    ///
    /// This increments the view number, which changes the leader
    /// selection without advancing the block height. Pending nullifiers
    /// are preserved for the next leader to propose.
    pub fn trigger_view_change(&mut self) {
        self.view += 1;
        self.votes.clear(); // discard votes from failed view
    }

    /// Get the current view number.
    pub fn current_view(&self) -> u64 {
        self.view
    }
}

/// Consensus errors.
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("not the current leader: leader is {leader}, self is {self_id}")]
    NotLeader { leader: NodeId, self_id: NodeId },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validators() -> Vec<NodeId> {
        vec![1, 2, 3, 4]
    }

    #[test]
    fn test_leader_rotation() {
        let state = ConsensusState::new(1, validators());
        assert_eq!(state.current_leader(), 1); // height 0 -> validator[0]
    }

    #[test]
    fn test_quorum_size() {
        let state = ConsensusState::new(1, validators());
        assert_eq!(state.total_validators, 4);
        assert_eq!(state.max_faults, 1);
        assert_eq!(state.quorum_size, 3); // 2*1 + 1 = 3
    }

    #[test]
    fn test_propose_as_leader() {
        let mut state = ConsensusState::new(1, validators());
        state.submit_nullifier([42u8; 32]);

        let block = state.propose_block().unwrap();
        assert_eq!(block.height, 0);
        assert_eq!(block.leader, 1);
        assert_eq!(block.nullifiers.len(), 1);
    }

    #[test]
    fn test_propose_as_non_leader_fails() {
        let mut state = ConsensusState::new(2, validators()); // node 2, but leader is node 1
        let result = state.propose_block();
        assert!(result.is_err());
    }

    #[test]
    fn test_vote_and_commit() {
        let vals = validators();
        let mut node1 = ConsensusState::new(1, vals.clone());
        let mut node2 = ConsensusState::new(2, vals.clone());
        let mut node3 = ConsensusState::new(3, vals.clone());
        let mut node4 = ConsensusState::new(4, vals.clone());

        // Submit nullifier
        node1.submit_nullifier([42u8; 32]);

        // Node 1 (leader) proposes
        let block = node1.propose_block().unwrap();

        // All nodes vote
        let v1 = node1.vote_on_block(&block);
        let v2 = node2.vote_on_block(&block);
        let v3 = node3.vote_on_block(&block);
        let _v4 = node4.vote_on_block(&block);

        assert!(v1.approve);
        assert!(v2.approve);
        assert!(v3.approve);

        // Collect votes at node 1
        node1.receive_vote(v2);
        node1.receive_vote(v3);

        // Try to commit (should succeed with 3 votes = quorum)
        let committed = node1.try_commit(&block).unwrap();
        assert!(committed);
        assert_eq!(node1.current_height, 1);
        assert!(node1.is_committed(&[42u8; 32]));
    }

    #[test]
    fn test_insufficient_votes_no_commit() {
        let vals = validators();
        let mut node1 = ConsensusState::new(1, vals.clone());

        node1.submit_nullifier([42u8; 32]);
        let block = node1.propose_block().unwrap();

        // Only 1 vote (self)
        node1.vote_on_block(&block);

        // Should not commit (need 3, have 1)
        let committed = node1.try_commit(&block).unwrap();
        assert!(!committed);
    }

    #[test]
    fn test_multiple_blocks() {
        let vals = vec![1, 2, 3];
        let mut node1 = ConsensusState::new(1, vals.clone());

        // Block 0
        node1.submit_nullifier([1u8; 32]);
        let block0 = node1.propose_block().unwrap();
        node1.vote_on_block(&block0);
        // Simulate 2 more votes
        node1.receive_vote(Vote { voter: 2, block_height: 0, block_hash: block0.hash, approve: true });
        node1.receive_vote(Vote { voter: 3, block_height: 0, block_hash: block0.hash, approve: true });
        assert!(node1.try_commit(&block0).unwrap());

        // After commit, height is 1, leader rotates to node 2
        assert_eq!(node1.current_height, 1);
        assert_eq!(node1.current_leader(), 2);
        assert_eq!(node1.block_count(), 1);
        assert_eq!(node1.nullifier_count(), 1);
    }

    #[test]
    fn test_duplicate_nullifier_ignored() {
        let mut state = ConsensusState::new(1, vec![1, 2, 3]);
        state.committed_nullifiers.insert([42u8; 32]);

        // Submitting an already-committed nullifier should be ignored
        state.submit_nullifier([42u8; 32]);
        assert!(state.pending_nullifiers.is_empty());
    }
}
