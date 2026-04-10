//! Nullifier system for double-spend detection.
//!
//! Each token has a unique nullifier derived from the owner's secret and the token ID.
//! When a token is spent, its nullifier is published. If the same nullifier appears
//! twice, double-spend is detected and the blame protocol can identify the cheater.

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use std::collections::HashSet;

/// Compute a nullifier from an owner's secret and a token ID.
///
/// nullifier = SHAKE-256("specter-nullifier:" || secret || token_id)
///
/// The nullifier is deterministic: the same secret + token_id always produces
/// the same nullifier. But given only the nullifier, the secret and token_id
/// cannot be recovered.
pub fn compute_nullifier(secret: &[u8; 32], token_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"specter-nullifier:");
    hasher.update(secret);
    hasher.update(token_id);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 32];
    reader.read(&mut output);
    output
}

/// A set of spent nullifiers for double-spend detection.
///
/// In a full system, this would be a distributed append-only log
/// maintained by the BFT consensus layer. For the prototype, it's
/// an in-memory HashSet.
pub struct NullifierSet {
    nullifiers: HashSet<[u8; 32]>,
}

impl NullifierSet {
    /// Create an empty nullifier set.
    pub fn new() -> Self {
        Self {
            nullifiers: HashSet::new(),
        }
    }

    /// Insert a nullifier. Returns `true` if the nullifier was new (valid spend).
    /// Returns `false` if the nullifier was already present (double-spend detected).
    pub fn insert(&mut self, nullifier: [u8; 32]) -> bool {
        self.nullifiers.insert(nullifier)
    }

    /// Check if a nullifier has been spent.
    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Number of spent nullifiers.
    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }
}

impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_deterministic() {
        let secret = [1u8; 32];
        let token_id = [2u8; 32];
        let n1 = compute_nullifier(&secret, &token_id);
        let n2 = compute_nullifier(&secret, &token_id);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_different_secrets_different_nullifiers() {
        let token_id = [0u8; 32];
        let n1 = compute_nullifier(&[1u8; 32], &token_id);
        let n2 = compute_nullifier(&[2u8; 32], &token_id);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_different_tokens_different_nullifiers() {
        let secret = [1u8; 32];
        let n1 = compute_nullifier(&secret, &[1u8; 32]);
        let n2 = compute_nullifier(&secret, &[2u8; 32]);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_nullifier_set_insert_and_detect() {
        let mut set = NullifierSet::new();
        let nullifier = [42u8; 32];

        assert!(set.insert(nullifier));  // first insert succeeds
        assert!(!set.insert(nullifier)); // second insert = double-spend
    }

    #[test]
    fn test_nullifier_set_contains() {
        let mut set = NullifierSet::new();
        let nullifier = [42u8; 32];

        assert!(!set.contains(&nullifier));
        set.insert(nullifier);
        assert!(set.contains(&nullifier));
    }

    #[test]
    fn test_nullifier_set_multiple() {
        let mut set = NullifierSet::new();
        for i in 0u8..10 {
            let mut n = [0u8; 32];
            n[0] = i;
            assert!(set.insert(n));
        }
        assert_eq!(set.len(), 10);
    }
}
