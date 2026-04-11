//! Shamir's Secret Sharing over Ristretto255 scalars.
//!
//! Splits a secret into n shares such that any t shares can reconstruct it,
//! but fewer than t shares reveal nothing. This is the foundation for
//! threshold signature schemes.

use curve25519_dalek::Scalar;
use zeroize::Zeroize;

use crate::scalar_utils::random_scalar;

/// A single share of a secret, identified by its x-coordinate.
#[derive(Clone)]
pub struct Share {
    /// The x-coordinate (evaluator index), must be nonzero.
    pub x: Scalar,
    /// The y-coordinate (polynomial evaluation at x). SECRET.
    pub y: Scalar,
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("x", &self.x)
            .field("y", &"[REDACTED]")
            .finish()
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

/// Errors for Shamir secret sharing.
#[derive(Debug, thiserror::Error)]
pub enum ShamirError {
    #[error("threshold must be > 0")]
    ZeroThreshold,
    #[error("threshold ({threshold}) must be <= total shares ({total})")]
    ThresholdExceedsTotal { threshold: usize, total: usize },
    #[error("total shares must be > 0")]
    ZeroShares,
}

/// Split a secret into `n` shares with threshold `t`.
///
/// Any `t` shares can reconstruct the secret; fewer reveal nothing.
pub fn split_secret(secret: &Scalar, t: usize, n: usize) -> Result<Vec<Share>, ShamirError> {
    if t == 0 { return Err(ShamirError::ZeroThreshold); }
    if n == 0 { return Err(ShamirError::ZeroShares); }
    if t > n { return Err(ShamirError::ThresholdExceedsTotal { threshold: t, total: n }); }

    // Build a random polynomial of degree t-1 with constant term = secret
    // p(x) = secret + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
    let mut coefficients = Vec::with_capacity(t);
    coefficients.push(*secret);
    for _ in 1..t {
        coefficients.push(random_scalar());
    }

    // Evaluate the polynomial at x = 1, 2, ..., n
    let shares: Vec<Share> = (1..=n)
        .map(|i| {
            let x = Scalar::from(i as u64);
            let y = evaluate_polynomial(&coefficients, &x);
            Share { x, y }
        })
        .collect();
    Ok(shares)
}

/// Reconstruct the secret from `t` or more shares using Lagrange interpolation.
///
/// Evaluates the interpolating polynomial at x=0 to recover the constant term (secret).
///
/// # Errors
/// Returns `None` if fewer than 2 shares are provided or shares have duplicate x-coordinates.
pub fn reconstruct_secret(shares: &[Share]) -> Option<Scalar> {
    if shares.is_empty() {
        return None;
    }

    // Check for duplicate x-coordinates
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].x == shares[j].x {
                return None;
            }
        }
    }

    // Lagrange interpolation at x = 0
    let mut secret = Scalar::ZERO;

    for i in 0..shares.len() {
        let xi = &shares[i].x;
        let yi = &shares[i].y;

        // Compute Lagrange basis polynomial L_i(0)
        // L_i(0) = product_{j != i} (0 - x_j) / (x_i - x_j)
        //        = product_{j != i} (-x_j) / (x_i - x_j)
        let mut basis = Scalar::ONE;
        for (j, share_j) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = &share_j.x;
            // numerator: (0 - x_j) = -x_j
            // denominator: (x_i - x_j)
            let num = -xj;
            let den = xi - xj;
            debug_assert_ne!(den, Scalar::ZERO, "duplicate x-coordinates should have been caught earlier");
            basis *= num * den.invert();
        }

        secret += yi * basis;
    }

    Some(secret)
}

/// Evaluate a polynomial at point x.
/// coefficients[0] is the constant term.
fn evaluate_polynomial(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    let mut result = Scalar::ZERO;
    let mut x_power = Scalar::ONE;

    for coeff in coefficients {
        result += coeff * x_power;
        x_power *= x;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar_utils::scalar_from_u64;

    #[test]
    fn test_split_and_reconstruct_2_of_3() {
        let secret = scalar_from_u64(42);
        let shares = split_secret(&secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // Any 2 shares should reconstruct
        let recovered = reconstruct_secret(&shares[0..2]).unwrap();
        assert_eq!(recovered, secret);

        let recovered = reconstruct_secret(&shares[1..3]).unwrap();
        assert_eq!(recovered, secret);

        let recovered = reconstruct_secret(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_split_and_reconstruct_3_of_5() {
        let secret = scalar_from_u64(12345);
        let shares = split_secret(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(recovered, secret);

        let recovered = reconstruct_secret(&shares[2..5]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_all_shares_reconstruct() {
        let secret = random_scalar();
        let shares = split_secret(&secret, 3, 5).unwrap();

        let recovered = reconstruct_secret(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_1_of_1() {
        let secret = scalar_from_u64(99);
        let shares = split_secret(&secret, 1, 1).unwrap();
        assert_eq!(shares.len(), 1);

        let recovered = reconstruct_secret(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_insufficient_shares_wrong_result() {
        let secret = scalar_from_u64(42);
        let shares = split_secret(&secret, 3, 5).unwrap();

        // Only 2 shares for a threshold-3 scheme: result should (almost certainly) be wrong
        let recovered = reconstruct_secret(&shares[0..2]).unwrap();
        assert_ne!(recovered, secret);
    }

    #[test]
    fn test_duplicate_x_rejected() {
        let share = Share {
            x: scalar_from_u64(1),
            y: scalar_from_u64(10),
        };
        let result = reconstruct_secret(&[share.clone(), share]);
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_shares() {
        let result = reconstruct_secret(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_random_secrets() {
        for _ in 0..20 {
            let secret = random_scalar();
            let shares = split_secret(&secret, 3, 5).unwrap();
            let recovered = reconstruct_secret(&shares[0..3]).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn test_zero_threshold_rejected() {
        let secret = scalar_from_u64(42);
        assert!(split_secret(&secret, 0, 3).is_err());
    }

    #[test]
    fn test_threshold_exceeds_total_rejected() {
        let secret = scalar_from_u64(42);
        assert!(split_secret(&secret, 5, 3).is_err());
    }

    #[test]
    fn test_zero_shares_rejected() {
        let secret = scalar_from_u64(42);
        assert!(split_secret(&secret, 0, 0).is_err());
    }
}
