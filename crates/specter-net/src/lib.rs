pub mod attestation;
pub mod consensus;
pub mod gossip;
pub mod node;
pub mod protocol;

/// Post-quantum hybrid consensus signatures (ML-DSA-65 alongside
/// classical Schnorr). Gated behind the `pq-consensus` feature.
#[cfg(feature = "pq-consensus")]
pub mod pq_consensus;
