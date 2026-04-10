//! Verifiable Delay Function (VDF) for time-locked tokens.
//!
//! A VDF proves that a minimum amount of wall-clock time has passed since
//! a token was issued or renewed. This prevents tokens from being used
//! offline indefinitely — after time T, the token expires and must be
//! renewed online.
//!
//! Implementation: iterated SHA-256 hashing. The prover computes
//! H(H(H(...H(seed)...))) for T iterations. Verification requires
//! recomputing the same chain (parallel-resistant by design).
//!
//! In production, this would use a number-theoretic VDF (e.g., repeated
//! squaring in a group of unknown order) which allows fast verification
//! via Wesolowski or Pietrzak proofs.

use sha2::{Digest, Sha256};

/// A VDF proof — proves that a specific number of sequential hash
/// iterations were computed starting from a seed.
#[derive(Clone, Debug)]
pub struct VdfProof {
    /// The seed (input).
    pub seed: [u8; 32],
    /// Number of iterations computed.
    pub iterations: u64,
    /// The final output after all iterations.
    pub output: [u8; 32],
}

/// Parameters for the VDF.
pub struct VdfParams {
    /// Number of iterations required (controls time delay).
    /// Higher = longer delay = longer offline validity.
    pub iterations: u64,
}

impl VdfParams {
    /// Create VDF parameters with the given iteration count.
    pub fn new(iterations: u64) -> Self {
        Self { iterations }
    }
}

/// Evaluate the VDF: compute T iterations of SHA-256 starting from seed.
///
/// This is intentionally slow — it proves that the prover spent time
/// computing the chain. The output is deterministic.
pub fn evaluate(seed: &[u8; 32], iterations: u64) -> VdfProof {
    let mut current = *seed;

    for _ in 0..iterations {
        let hash = Sha256::digest(&current);
        current.copy_from_slice(&hash);
    }

    VdfProof {
        seed: *seed,
        iterations,
        output: current,
    }
}

/// Verify a VDF proof by recomputing the hash chain.
///
/// In this prototype, verification has the same cost as evaluation.
/// In production (with Wesolowski/Pietrzak), verification would be O(log T).
pub fn verify(proof: &VdfProof) -> bool {
    let recomputed = evaluate(&proof.seed, proof.iterations);
    recomputed.output == proof.output
}

/// Check if a VDF proof has "expired" — i.e., it was computed with
/// fewer iterations than required by the current parameters.
pub fn is_expired(proof: &VdfProof, required_iterations: u64) -> bool {
    proof.iterations < required_iterations
}

/// Create a time-lock seed from a token ID and timestamp.
pub fn create_seed(token_id: &[u8; 32], timestamp_secs: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"specter-vdf-seed:");
    hasher.update(token_id);
    hasher.update(&timestamp_secs.to_le_bytes());
    let hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_and_verify() {
        let seed = [42u8; 32];
        let proof = evaluate(&seed, 100);
        assert!(verify(&proof));
    }

    #[test]
    fn test_deterministic() {
        let seed = [1u8; 32];
        let p1 = evaluate(&seed, 50);
        let p2 = evaluate(&seed, 50);
        assert_eq!(p1.output, p2.output);
    }

    #[test]
    fn test_different_seeds() {
        let p1 = evaluate(&[1u8; 32], 50);
        let p2 = evaluate(&[2u8; 32], 50);
        assert_ne!(p1.output, p2.output);
    }

    #[test]
    fn test_different_iterations() {
        let seed = [1u8; 32];
        let p1 = evaluate(&seed, 50);
        let p2 = evaluate(&seed, 100);
        assert_ne!(p1.output, p2.output);
    }

    #[test]
    fn test_tampered_output_fails() {
        let seed = [1u8; 32];
        let mut proof = evaluate(&seed, 50);
        proof.output[0] ^= 0xFF;
        assert!(!verify(&proof));
    }

    #[test]
    fn test_is_expired() {
        let proof = evaluate(&[1u8; 32], 50);
        assert!(!is_expired(&proof, 50));
        assert!(!is_expired(&proof, 30));
        assert!(is_expired(&proof, 100));
    }

    #[test]
    fn test_create_seed() {
        let token_id = [99u8; 32];
        let s1 = create_seed(&token_id, 1000);
        let s2 = create_seed(&token_id, 2000);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_zero_iterations() {
        let seed = [1u8; 32];
        let proof = evaluate(&seed, 0);
        assert_eq!(proof.output, seed);
        assert!(verify(&proof));
    }
}
