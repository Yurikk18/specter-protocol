//! Network protocol message types for the Specter P2P network.

/// Unique node identifier.
pub type NodeId = u64;

/// Messages exchanged between nodes in the Specter network.
#[derive(Clone, Debug)]
pub enum Message {
    /// Request to mint a new token (sent to threshold signers).
    MintRequest {
        requester: NodeId,
        blinded_message: Vec<u8>,
    },

    /// Partial signature response from a threshold signer.
    MintResponse {
        signer_id: NodeId,
        partial_signature: Vec<u8>,
    },

    /// Broadcast a spent nullifier to the network.
    /// Includes a Schnorr signature proving the sender authored this broadcast.
    NullifierBroadcast {
        nullifier: [u8; 32],
        sender: NodeId,
        /// Schnorr signature (R, s) over SHA-256("specter-gossip:" || nullifier || sender).
        /// Verifiers check this against the sender's registered public key.
        signature_r: [u8; 32],
        signature_s: [u8; 32],
    },

    /// Request the current nullifier set (or a diff since a known state).
    SyncRequest {
        from_node: NodeId,
        last_known_block: u64,
    },

    /// Response with nullifier set updates.
    SyncResponse {
        nullifiers: Vec<[u8; 32]>,
        block_height: u64,
    },

    /// Consensus proposal for a new block of nullifiers.
    ConsensusProposal {
        leader: NodeId,
        block_height: u64,
        nullifiers: Vec<[u8; 32]>,
        proposal_hash: [u8; 32],
    },

    /// Vote on a consensus proposal.
    ConsensusVote {
        voter: NodeId,
        block_height: u64,
        proposal_hash: [u8; 32],
        approve: bool,
    },

    /// Heartbeat / keep-alive.
    Ping { from: NodeId },
    Pong { from: NodeId },
}

impl Message {
    /// Get the message type name (for logging).
    pub fn type_name(&self) -> &'static str {
        match self {
            Message::MintRequest { .. } => "MintRequest",
            Message::MintResponse { .. } => "MintResponse",
            Message::NullifierBroadcast { .. } => "NullifierBroadcast",
            Message::SyncRequest { .. } => "SyncRequest",
            Message::SyncResponse { .. } => "SyncResponse",
            Message::ConsensusProposal { .. } => "ConsensusProposal",
            Message::ConsensusVote { .. } => "ConsensusVote",
            Message::Ping { .. } => "Ping",
            Message::Pong { .. } => "Pong",
        }
    }
}
