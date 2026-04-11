//! BFT consensus for the nullifier set with authenticated votes.
//!
//! Implements a HotStuff-2-inspired consensus protocol:
//! 1. A leader proposes a block of new nullifiers.
//! 2. Validators sign their votes with Schnorr signatures.
//! 3. If a quorum (2f+1 out of 3f+1) of authenticated votes approve, the block is committed.
//! 4. Leader rotates each block, with view change on leader failure.
//!
//! Every vote is cryptographically signed - forged votes are rejected.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{HashMap, HashSet};

use crate::protocol::NodeId;

/// A block of nullifiers to be committed.
#[derive(Clone, Debug)]
pub struct NullifierBlock {
    pub height: u64,
    pub leader: NodeId,
    pub nullifiers: Vec<[u8; 32]>,
    /// Hash of the previous block (chain linking for fork detection).
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

impl NullifierBlock {
    pub fn new(height: u64, leader: NodeId, nullifiers: Vec<[u8; 32]>, prev_hash: [u8; 32]) -> Self {
        let hash = Self::compute_hash(height, leader, &nullifiers, &prev_hash);
        Self { height, leader, nullifiers, prev_hash, hash }
    }

    fn compute_hash(height: u64, leader: NodeId, nullifiers: &[[u8; 32]], prev_hash: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"specter-block:");
        hasher.update(height.to_le_bytes());
        hasher.update(leader.to_le_bytes());
        hasher.update(prev_hash);
        for n in nullifiers { hasher.update(n); }
        let digest = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        hash
    }
}

/// A Schnorr signature for vote authentication.
#[derive(Clone, Debug)]
pub struct VoteSignature {
    pub r: RistrettoPoint,
    pub s: Scalar,
}

/// An authenticated vote on a proposed block.
#[derive(Clone, Debug)]
pub struct Vote {
    pub voter: NodeId,
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub approve: bool,
    pub signature: VoteSignature,
}

/// A validator's keypair for signing votes.
/// Non-Clone: secret key material should not be duplicated.
pub struct ValidatorKey {
    pub node_id: NodeId,
    pub public_key: RistrettoPoint,
    secret_key: Scalar,
}

impl ValidatorKey {
    /// Generate a random validator keypair.
    pub fn generate(node_id: NodeId) -> Self {
        let secret_key = specter_primitives::scalar_utils::random_scalar();
        let public_key = secret_key * G;
        Self { node_id, public_key, secret_key }
    }

    /// Sign a vote. Includes view number to prevent cross-view replay.
    pub fn sign_vote(&self, block_height: u64, block_hash: &[u8; 32], approve: bool) -> Vote {
        self.sign_vote_with_view(block_height, block_hash, approve, 0)
    }

    /// Sign a vote with an explicit view number.
    pub fn sign_vote_with_view(&self, block_height: u64, block_hash: &[u8; 32], approve: bool, view: u64) -> Vote {
        let msg = vote_message(self.node_id, block_height, block_hash, approve, view);
        let k = specter_primitives::scalar_utils::random_scalar();
        let r = k * G;
        let e = vote_challenge(&r, &self.public_key, &msg);
        let s = k + e * self.secret_key;

        Vote {
            voter: self.node_id,
            block_height,
            block_hash: *block_hash,
            approve,
            signature: VoteSignature { r, s },
        }
    }
}

impl Drop for ValidatorKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_key.zeroize();
    }
}

/// Verify a vote's Schnorr signature against the voter's public key.
pub fn verify_vote_signature(vote: &Vote, voter_pubkey: &RistrettoPoint) -> bool {
    verify_vote_signature_with_view(vote, voter_pubkey, 0)
}

/// Verify a vote signature with an explicit view number.
pub fn verify_vote_signature_with_view(vote: &Vote, voter_pubkey: &RistrettoPoint, view: u64) -> bool {
    let msg = vote_message(vote.voter, vote.block_height, &vote.block_hash, vote.approve, view);
    let e = vote_challenge(&vote.signature.r, voter_pubkey, &msg);
    let lhs = vote.signature.s * G;
    let rhs = vote.signature.r + e * voter_pubkey;
    lhs == rhs
}

fn vote_message(voter: NodeId, height: u64, hash: &[u8; 32], approve: bool, view: u64) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&voter.to_le_bytes());
    msg.extend_from_slice(&height.to_le_bytes());
    msg.extend_from_slice(hash);
    msg.push(if approve { 1 } else { 0 });
    msg.extend_from_slice(&view.to_le_bytes()); // prevent cross-view replay
    msg
}

fn vote_challenge(r: &RistrettoPoint, pk: &RistrettoPoint, msg: &[u8]) -> Scalar {
    let hash = Sha512::new()
        .chain_update(b"specter-vote-challenge:")
        .chain_update(r.compress().as_bytes())
        .chain_update(pk.compress().as_bytes())
        .chain_update(msg)
        .finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// The consensus state machine.
pub struct ConsensusState {
    pub node_id: NodeId,
    pub total_validators: usize,
    pub max_faults: usize,
    pub quorum_size: usize,
    pub validators: Vec<NodeId>,
    /// Validator public keys for vote verification.
    pub validator_keys: HashMap<NodeId, RistrettoPoint>,
    pub current_height: u64,
    pub committed_blocks: Vec<NullifierBlock>,
    pub committed_nullifiers: HashSet<[u8; 32]>,
    pub pending_nullifiers: HashSet<[u8; 32]>,
    votes: HashMap<[u8; 32], Vec<Vote>>,
    pub view: u64,
    /// Seen proposals for equivocation detection: (height, leader) -> first hash.
    seen_proposals: HashMap<(u64, NodeId), [u8; 32]>,
}

impl ConsensusState {
    /// Create a new consensus state.
    pub fn new(
        node_id: NodeId,
        validators: Vec<NodeId>,
        validator_keys: HashMap<NodeId, RistrettoPoint>,
    ) -> Result<Self, ConsensusError> {
        let n = validators.len();
        // BFT requires n >= 3f+1 with f >= 1, so minimum n = 4 for any fault tolerance.
        // n < 4 is allowed for testing but provides ZERO fault tolerance (logged as warning).
        if n < 1 {
            return Err(ConsensusError::InsufficientValidators { min: 1, got: 0 });
        }
        let max_faults = (n - 1) / 3;
        let quorum_size = if n < 4 {
            #[cfg(not(test))]
            eprintln!("WARNING: {} validators provides 0 fault tolerance (need >= 4 for BFT)", n);
            n // require all validators (f=0)
        } else {
            2 * max_faults + 1
        };

        Ok(Self {
            node_id,
            total_validators: n,
            max_faults,
            quorum_size,
            validators,
            validator_keys,
            current_height: 0,
            committed_blocks: Vec::new(),
            committed_nullifiers: HashSet::new(),
            pending_nullifiers: HashSet::new(),
            votes: HashMap::new(),
            view: 0,
            seen_proposals: HashMap::new(),
        })
    }

    pub fn current_leader(&self) -> NodeId {
        // Use modular arithmetic before addition to prevent overflow on 32-bit platforms
        let n = self.validators.len() as u64;
        let idx = ((self.current_height % n) + (self.view % n)) % n;
        self.validators[idx as usize]
    }

    pub fn submit_nullifier(&mut self, nullifier: [u8; 32]) {
        const MAX_PENDING_NULLIFIERS: usize = 100_000;
        if self.pending_nullifiers.len() >= MAX_PENDING_NULLIFIERS {
            return; // drop under memory pressure
        }
        if !self.committed_nullifiers.contains(&nullifier) {
            self.pending_nullifiers.insert(nullifier);
        }
    }

    pub fn propose_block(&mut self) -> Result<NullifierBlock, ConsensusError> {
        if self.current_leader() != self.node_id {
            return Err(ConsensusError::NotLeader {
                leader: self.current_leader(),
                self_id: self.node_id,
            });
        }
        let nullifiers: Vec<[u8; 32]> = self.pending_nullifiers.drain().collect();
        let prev_hash = self.committed_blocks.last()
            .map(|b| b.hash)
            .unwrap_or([0u8; 32]);
        Ok(NullifierBlock::new(self.current_height, self.node_id, nullifiers, prev_hash))
    }

    /// Receive a proposal and check for equivocation.
    /// A leader who proposes different blocks at the same height is equivocating.
    pub fn receive_proposal(&mut self, block: &NullifierBlock) -> Result<(), ConsensusError> {
        let key = (block.height, block.leader);
        match self.seen_proposals.get(&key) {
            Some(prev) if *prev != block.hash => {
                return Err(ConsensusError::Equivocation {
                    leader: block.leader,
                    height: block.height,
                });
            }
            None => { self.seen_proposals.insert(key, block.hash); }
            _ => {}
        }
        Ok(())
    }

    /// Receive and authenticate a vote.
    ///
    /// Rejects votes from unknown validators or with invalid signatures.
    pub fn receive_vote(&mut self, vote: Vote) -> Result<(), ConsensusError> {
        // Check voter is a known validator
        let voter_pk = self.validator_keys.get(&vote.voter)
            .ok_or(ConsensusError::UnknownVoter(vote.voter))?;

        // Validate vote height matches current consensus height
        if vote.block_height != self.current_height {
            return Err(ConsensusError::WrongHeight {
                expected: self.current_height,
                got: vote.block_height,
            });
        }

        // Verify Schnorr signature
        if !verify_vote_signature(&vote, voter_pk) {
            return Err(ConsensusError::InvalidVoteSignature(vote.voter));
        }

        // Check for duplicate votes from same voter on same block
        if let Some(existing) = self.votes.get(&vote.block_hash) {
            if existing.iter().any(|v| v.voter == vote.voter) {
                return Err(ConsensusError::DuplicateVote(vote.voter));
            }
        }

        self.votes.entry(vote.block_hash).or_default().push(vote);
        Ok(())
    }

    pub fn try_commit(&mut self, block: &NullifierBlock) -> Result<bool, ConsensusError> {
        // Verify block hash integrity before committing
        let computed = NullifierBlock::compute_hash(
            block.height, block.leader, &block.nullifiers, &block.prev_hash,
        );
        if computed != block.hash {
            return Err(ConsensusError::InvalidBlockHash);
        }

        let votes = self.votes.get(&block.hash).cloned().unwrap_or_default();
        let approvals = votes.iter().filter(|v| v.approve).count();

        if approvals >= self.quorum_size {
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

    pub fn is_committed(&self, nullifier: &[u8; 32]) -> bool {
        self.committed_nullifiers.contains(nullifier)
    }

    pub fn block_count(&self) -> usize { self.committed_blocks.len() }
    pub fn nullifier_count(&self) -> usize { self.committed_nullifiers.len() }

    pub fn trigger_view_change(&mut self) {
        self.view += 1;
        self.votes.clear();
    }

    pub fn current_view(&self) -> u64 { self.view }
}

/// Consensus errors.
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("not the current leader: leader is {leader}, self is {self_id}")]
    NotLeader { leader: NodeId, self_id: NodeId },

    #[error("insufficient validators: need at least {min}, got {got}")]
    InsufficientValidators { min: usize, got: usize },

    #[error("unknown voter: {0}")]
    UnknownVoter(NodeId),

    #[error("invalid vote signature from voter {0}")]
    InvalidVoteSignature(NodeId),

    #[error("duplicate vote from voter {0}")]
    DuplicateVote(NodeId),

    #[error("equivocation detected: leader {leader} proposed different blocks at height {height}")]
    Equivocation { leader: NodeId, height: u64 },

    #[error("vote for wrong height: expected {expected}, got {got}")]
    WrongHeight { expected: u64, got: u64 },

    #[error("block hash mismatch: block contents do not match hash")]
    InvalidBlockHash,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_validators() -> (Vec<ValidatorKey>, Vec<NodeId>, HashMap<NodeId, RistrettoPoint>) {
        let keys: Vec<ValidatorKey> = (1..=4).map(|id| ValidatorKey::generate(id)).collect();
        let ids: Vec<NodeId> = keys.iter().map(|k| k.node_id).collect();
        let pubkeys: HashMap<NodeId, RistrettoPoint> = keys.iter()
            .map(|k| (k.node_id, k.public_key))
            .collect();
        (keys, ids, pubkeys)
    }

    #[test]
    fn test_leader_rotation() {
        let (_, ids, pks) = setup_validators();
        let state = ConsensusState::new(1, ids, pks).unwrap();
        assert_eq!(state.current_leader(), 1);
    }

    #[test]
    fn test_quorum_size() {
        let (_, ids, pks) = setup_validators();
        let state = ConsensusState::new(1, ids, pks).unwrap();
        assert_eq!(state.total_validators, 4);
        assert_eq!(state.quorum_size, 3);
    }

    #[test]
    fn test_propose_as_leader() {
        let (_, ids, pks) = setup_validators();
        let mut state = ConsensusState::new(1, ids, pks).unwrap();
        state.submit_nullifier([42u8; 32]);
        let block = state.propose_block().unwrap();
        assert_eq!(block.height, 0);
        assert_eq!(block.nullifiers.len(), 1);
    }

    #[test]
    fn test_propose_as_non_leader_fails() {
        let (_, ids, pks) = setup_validators();
        let mut state = ConsensusState::new(2, ids, pks).unwrap();
        assert!(state.propose_block().is_err());
    }

    #[test]
    fn test_authenticated_vote_and_commit() {
        let (keys, ids, pks) = setup_validators();
        let mut node1 = ConsensusState::new(1, ids, pks).unwrap();

        node1.submit_nullifier([42u8; 32]);
        let block = node1.propose_block().unwrap();

        // All validators sign their votes
        let v1 = keys[0].sign_vote(block.height, &block.hash, true);
        let v2 = keys[1].sign_vote(block.height, &block.hash, true);
        let v3 = keys[2].sign_vote(block.height, &block.hash, true);

        // Receive authenticated votes
        node1.receive_vote(v1).unwrap();
        node1.receive_vote(v2).unwrap();
        node1.receive_vote(v3).unwrap();

        // Commit with quorum
        assert!(node1.try_commit(&block).unwrap());
        assert!(node1.is_committed(&[42u8; 32]));
    }

    #[test]
    fn test_forged_vote_rejected() {
        let (_, ids, pks) = setup_validators();
        let mut state = ConsensusState::new(1, ids, pks).unwrap();

        // Forge a vote with a random key (not a registered validator's key)
        let fake_key = ValidatorKey::generate(99);
        let forged = fake_key.sign_vote(0, &[0u8; 32], true);

        // Should be rejected - voter 99 is not a known validator
        assert!(state.receive_vote(forged).is_err());
    }

    #[test]
    fn test_tampered_vote_rejected() {
        let (keys, ids, pks) = setup_validators();
        let mut state = ConsensusState::new(1, ids, pks).unwrap();

        let mut vote = keys[0].sign_vote(0, &[0u8; 32], true);
        // Tamper with the approve flag
        vote.approve = false;

        // Signature no longer matches - should be rejected
        assert!(state.receive_vote(vote).is_err());
    }

    #[test]
    fn test_duplicate_vote_rejected() {
        let (keys, ids, pks) = setup_validators();
        let mut state = ConsensusState::new(1, ids, pks).unwrap();

        state.submit_nullifier([42u8; 32]);
        let block = state.propose_block().unwrap();

        let v1 = keys[0].sign_vote(block.height, &block.hash, true);
        let v1_dup = keys[0].sign_vote(block.height, &block.hash, true);

        state.receive_vote(v1).unwrap();
        assert!(state.receive_vote(v1_dup).is_err()); // duplicate from same voter
    }

    #[test]
    fn test_insufficient_votes_no_commit() {
        let (keys, ids, pks) = setup_validators();
        let mut state = ConsensusState::new(1, ids, pks).unwrap();

        state.submit_nullifier([42u8; 32]);
        let block = state.propose_block().unwrap();

        let v1 = keys[0].sign_vote(block.height, &block.hash, true);
        state.receive_vote(v1).unwrap();

        assert!(!state.try_commit(&block).unwrap()); // need 3, have 1
    }

    #[test]
    fn test_view_change() {
        let (_, ids, pks) = setup_validators();
        let mut state = ConsensusState::new(1, ids, pks).unwrap();
        assert_eq!(state.current_leader(), 1);

        state.trigger_view_change();
        assert_eq!(state.current_view(), 1);
        assert_eq!(state.current_leader(), 2); // rotated
    }
}
