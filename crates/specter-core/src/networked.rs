//! Networked protocol - integrates core operations with the P2P layer.
//!
//! Wraps Mint + NetworkNode so that minting publishes to the network,
//! transfers broadcast nullifiers via gossip, and the consensus layer
//! commits nullifiers in blocks.

use specter_credential::credential::Attributes;
use specter_net::consensus::{ValidatorKey, Vote};
use specter_net::node::NetworkNode;
use specter_net::protocol::NodeId;
use specter_offline::bonds::BondRegistry;

use crate::mint::{Mint, MintConfig};
use crate::nullifier::NullifierSet;
use crate::token::ProofCarryingToken;
use crate::transfer::{self, TransferResult};
use crate::verify::{self, VerificationResult};

/// A networked Specter node - combines mint, network, and bonds.
pub struct NetworkedNode {
    pub mint: Mint,
    pub network: NetworkNode,
    pub bonds: BondRegistry,
    pub nullifier_set: NullifierSet,
}

impl NetworkedNode {
    /// Create a new networked node with validator keys.
    pub fn new(
        node_id: NodeId,
        peers: Vec<NodeId>,
        validator_keys: Vec<ValidatorKey>,
        mint_config: MintConfig,
    ) -> Self {
        Self {
            mint: Mint::setup(mint_config),
            network: NetworkNode::new(node_id, peers, validator_keys),
            bonds: BondRegistry::new(),
            nullifier_set: NullifierSet::new(),
        }
    }

    /// Issue a token and broadcast genesis to the network.
    pub fn mint_token(
        &mut self,
        value: u64,
        signers: &[u64],
        attributes: Option<&Attributes>,
        vdf_iterations: Option<u64>,
        bond_owner_id: Option<[u8; 32]>,
    ) -> Result<ProofCarryingToken, String> {
        let token = self
            .mint
            .issue_full(value, signers, attributes, vdf_iterations, bond_owner_id)
            .map_err(|e| e.to_string())?;
        Ok(token)
    }

    /// Transfer a token and publish the nullifier to the network.
    pub fn transfer_token(
        &mut self,
        token: ProofCarryingToken,
    ) -> Result<TransferResult, String> {
        let result = transfer::transfer(token, &mut self.nullifier_set).map_err(|e| e.to_string())?;

        // Broadcast nullifier via gossip
        self.network.submit_nullifier(result.spent_nullifier);

        // Submit to consensus pending pool
        self.network
            .consensus
            .submit_nullifier(result.spent_nullifier);

        Ok(result)
    }

    /// Verify a token against this node's mint and network state.
    pub fn verify_token(&self, token: &ProofCarryingToken, current_time: u64) -> VerificationResult {
        verify::verify_token(
            token,
            &self.mint.group_public_key(),
            &self.mint.pedersen,
            &self.mint.credential_issuer.pedersen,
            current_time,
        )
    }

    /// Check if a nullifier is known to this node (gossip or committed).
    pub fn is_double_spend(&self, nullifier: &[u8; 32]) -> bool {
        self.network.is_nullifier_known(nullifier)
    }

    /// Propose a consensus block (only if this node is the leader).
    pub fn propose_block(
        &mut self,
    ) -> Result<specter_net::consensus::NullifierBlock, String> {
        self.network
            .consensus
            .propose_block()
            .map_err(|e| e.to_string())
    }

    /// Sign a vote on a proposed block using this node's validator key.
    pub fn sign_vote(
        &self,
        block: &specter_net::consensus::NullifierBlock,
    ) -> Vote {
        self.network.sign_vote(block.height, &block.hash, true)
    }

    /// Try to commit a block if quorum is reached.
    pub fn try_commit(
        &mut self,
        block: &specter_net::consensus::NullifierBlock,
    ) -> Result<bool, String> {
        self.network
            .consensus
            .try_commit(block)
            .map_err(|e| e.to_string())
    }

    /// Receive and authenticate a vote from another node.
    pub fn receive_vote(&mut self, vote: Vote) -> Result<(), String> {
        self.network.consensus.receive_vote(vote).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keys() -> Vec<ValidatorKey> {
        vec![
            ValidatorKey::generate(1),
            ValidatorKey::generate(2),
            ValidatorKey::generate(3),
        ]
    }

    fn make_node(id: NodeId, keys: Vec<ValidatorKey>) -> NetworkedNode {
        NetworkedNode::new(
            id,
            vec![1, 2, 3].into_iter().filter(|&x| x != id).collect(),
            keys,
            MintConfig {
                threshold: 2,
                total_signers: 3,
                recursion_bound: 20,
            },
        )
    }

    #[test]
    fn test_mint_and_verify() {
        let mut node = make_node(1, make_keys());
        let token = node.mint_token(1000, &[1, 2], None, None, None).unwrap();
        let vr = node.verify_token(&token, 0);
        assert!(vr.all_valid());
    }

    #[test]
    fn test_transfer_broadcasts_nullifier() {
        let mut node = make_node(1, make_keys());
        let token = node.mint_token(1000, &[1, 2], None, None, None).unwrap();

        let result = node.transfer_token(token).unwrap();

        // Nullifier should be in gossip
        assert!(node.is_double_spend(&result.spent_nullifier));

        // Token should still verify
        let vr = node.verify_token(&result.token, 0);
        assert!(vr.all_valid());
    }

    #[test]
    fn test_double_spend_via_network() {
        let mut node = make_node(1, make_keys());
        let token = node.mint_token(1000, &[1, 2], None, None, None).unwrap();

        let r1 = node.transfer_token(token).unwrap();
        // Nullifier already known after first transfer
        assert!(node.is_double_spend(&r1.spent_nullifier));
    }

    #[test]
    fn test_consensus_flow() {
        let keys = make_keys();
        let mut node1 = make_node(1, keys.clone());
        let node2 = make_node(2, keys.clone());
        let node3 = make_node(3, keys);

        let token = node1.mint_token(1000, &[1, 2], None, None, None).unwrap();
        let result = node1.transfer_token(token).unwrap();

        let block = node1.propose_block().unwrap();

        // Authenticated votes
        let v1 = node1.network.sign_vote(block.height, &block.hash, true);
        let v2 = node2.network.sign_vote(block.height, &block.hash, true);
        let v3 = node3.network.sign_vote(block.height, &block.hash, true);

        node1.receive_vote(v1).unwrap();
        node1.receive_vote(v2).unwrap();
        node1.receive_vote(v3).unwrap();

        assert!(node1.try_commit(&block).unwrap());
        assert!(node1.network.consensus.is_committed(&result.spent_nullifier));
    }

    #[test]
    fn test_full_networked_lifecycle() {
        let mut node = make_node(1, make_keys());

        // Issue with all features
        let attrs = Attributes {
            kyc_passed: true,
            not_sanctioned: true,
            jurisdiction: "EU".to_string(),
            age_over_18: true,
            expires_at: 0,
        };
        let bond_owner = [42u8; 32];
        node.bonds.deposit(bond_owner, 5000).unwrap();

        let token = node
            .mint_token(1000, &[1, 2], Some(&attrs), Some(50), Some(bond_owner))
            .unwrap();

        assert!(token.has_credential());
        assert!(token.has_bond());
        assert!(!token.is_vdf_expired(50));

        // Transfer 5 times
        let mut current = token;
        for _ in 0..5 {
            let result = node.transfer_token(current).unwrap();
            let vr = node.verify_token(&result.token, 0);
            assert!(vr.all_valid());
            current = result.token;
        }

        assert_eq!(current.transfer_count, 5);
        assert_eq!(current.fold_proof.steps, 5);

        // Bond coverage check
        assert!(node.bonds.check_coverage(&bond_owner, 1000));
    }
}
