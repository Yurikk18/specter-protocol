//! Simplified SIS (Short Integer Solution) commitment scheme.
//!
//! This is a learning exercise to build intuition for lattice-based commitments.
//! It implements a toy SIS commitment over integers mod q using a random matrix A.
//!
//! The SIS problem: given A, find a short vector x such that A*x = 0 mod q.
//! This hardness assumption underlies lattice-based commitment schemes.
//!
//! **NOT for production use** — uses small parameters for educational purposes.

use rand::Rng;

/// Parameters for the SIS commitment scheme.
pub struct SisParams {
    /// Modulus (a prime number).
    pub q: u64,
    /// Number of rows (security parameter).
    pub n: usize,
    /// Number of columns (message length).
    pub m: usize,
    /// The random matrix A (n x m) with entries in Z_q.
    pub matrix_a: Vec<Vec<u64>>,
    /// Shortness bound: message entries must be in [-beta, beta].
    pub beta: u64,
}

/// A SIS commitment is a vector in Z_q^n.
pub type SisCommitment = Vec<u64>;

impl SisParams {
    /// Generate random SIS parameters with a uniformly random matrix A.
    ///
    /// # Arguments
    /// * `n` — rows (security parameter, typically 4-8 for toy)
    /// * `m` — columns (message length, typically 8-16 for toy)
    /// * `q` — modulus (a prime, e.g., 65537)
    /// * `beta` — shortness bound for message entries
    pub fn generate(n: usize, m: usize, q: u64, beta: u64) -> Self {
        let mut rng = rand::thread_rng();
        let matrix_a: Vec<Vec<u64>> = (0..n)
            .map(|_| (0..m).map(|_| rng.gen_range(0..q)).collect())
            .collect();

        Self {
            q,
            n,
            m,
            matrix_a,
            beta,
        }
    }

    /// Commit to a message vector: C = A * message mod q.
    ///
    /// The message must have exactly `m` entries, each in [0, beta].
    pub fn commit(&self, message: &[u64]) -> Result<SisCommitment, SisError> {
        if message.len() != self.m {
            return Err(SisError::WrongMessageLength {
                expected: self.m,
                got: message.len(),
            });
        }

        for (i, &val) in message.iter().enumerate() {
            if val > self.beta {
                return Err(SisError::MessageNotShort {
                    index: i,
                    value: val,
                    beta: self.beta,
                });
            }
        }

        let commitment = (0..self.n)
            .map(|i| {
                let row = &self.matrix_a[i];
                let mut sum: u128 = 0;
                for j in 0..self.m {
                    sum += (row[j] as u128) * (message[j] as u128);
                }
                (sum % self.q as u128) as u64
            })
            .collect();

        Ok(commitment)
    }

    /// Verify that a commitment opens to the given message.
    ///
    /// Checks both correctness (A*message == commitment mod q) and
    /// shortness (all message entries <= beta).
    pub fn verify_opening(
        &self,
        commitment: &SisCommitment,
        message: &[u64],
    ) -> Result<bool, SisError> {
        let recomputed = self.commit(message)?;
        Ok(recomputed == *commitment)
    }
}

/// Errors for the SIS commitment scheme.
#[derive(Debug, thiserror::Error)]
pub enum SisError {
    #[error("wrong message length: expected {expected}, got {got}")]
    WrongMessageLength { expected: usize, got: usize },

    #[error("message entry at index {index} is {value}, exceeds shortness bound beta={beta}")]
    MessageNotShort { index: usize, value: u64, beta: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toy_params() -> SisParams {
        // Small parameters for testing
        SisParams::generate(4, 8, 65537, 100)
    }

    #[test]
    fn test_commitment_roundtrip() {
        let params = toy_params();
        let message = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let commitment = params.commit(&message).unwrap();
        assert!(params.verify_opening(&commitment, &message).unwrap());
    }

    #[test]
    fn test_wrong_message_fails() {
        let params = toy_params();
        let message = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let commitment = params.commit(&message).unwrap();

        let wrong = vec![1, 2, 3, 4, 5, 6, 7, 9];
        assert!(!params.verify_opening(&commitment, &wrong).unwrap());
    }

    #[test]
    fn test_wrong_length_rejected() {
        let params = toy_params();
        let short_message = vec![1, 2, 3];
        assert!(params.commit(&short_message).is_err());
    }

    #[test]
    fn test_non_short_message_rejected() {
        let params = toy_params();
        let message = vec![1, 2, 3, 4, 5, 6, 7, 999]; // 999 > beta=100
        assert!(params.commit(&message).is_err());
    }

    #[test]
    fn test_different_messages_different_commitments() {
        let params = toy_params();
        let m1 = vec![1, 0, 0, 0, 0, 0, 0, 0];
        let m2 = vec![0, 1, 0, 0, 0, 0, 0, 0];
        let c1 = params.commit(&m1).unwrap();
        let c2 = params.commit(&m2).unwrap();
        // With overwhelming probability these are different
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_zero_message_commits_to_zero() {
        let params = toy_params();
        let zero = vec![0; 8];
        let commitment = params.commit(&zero).unwrap();
        assert!(commitment.iter().all(|&v| v == 0));
    }

    #[test]
    fn test_commitment_deterministic() {
        let params = toy_params();
        let message = vec![10, 20, 30, 40, 50, 60, 70, 80];
        let c1 = params.commit(&message).unwrap();
        let c2 = params.commit(&message).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_many_random_messages() {
        let params = toy_params();
        let mut rng = rand::thread_rng();
        for _ in 0..50 {
            let message: Vec<u64> = (0..8).map(|_| rng.gen_range(0..=100)).collect();
            let commitment = params.commit(&message).unwrap();
            assert!(params.verify_opening(&commitment, &message).unwrap());
        }
    }
}
