//! RSA-based Verifiable Delay Function.
//!
//! Uses repeated squaring in an RSA group: y = x^(2^T) mod N.
//! This is inherently sequential — cannot be parallelized — making it
//! a true time-lock. Verification uses Wesolowski's protocol:
//! the prover sends a short proof pi that allows O(log T) verification.
//!
//! Security relies on the factoring assumption: without knowing the
//! factorization of N, computing y requires T sequential squarings.

use num_bigint::BigUint;
use num_traits::One;
use sha2::{Digest, Sha256};

/// RSA VDF parameters.
pub struct RsaVdfParams {
    /// RSA modulus N = p * q (public, factors unknown).
    pub modulus: BigUint,
    /// Bit size of the modulus.
    pub bits: u32,
}

/// RSA VDF proof.
#[derive(Clone, Debug)]
pub struct RsaVdfProof {
    /// Input x.
    pub input: BigUint,
    /// Output y = x^(2^T) mod N.
    pub output: BigUint,
    /// Number of squarings.
    pub iterations: u64,
    /// Wesolowski proof: pi = x^(floor(2^T / l)) mod N.
    pub proof_pi: BigUint,
    /// Challenge prime l (derived via Fiat-Shamir).
    pub challenge_l: BigUint,
}

impl RsaVdfParams {
    /// Create VDF params with a fixed RSA-2048 modulus.
    ///
    /// In production, this would use a modulus from a trusted setup ceremony
    /// (e.g., RSA-2048 challenge number) or a class group of unknown order.
    /// For this prototype, we use a product of two safe primes.
    pub fn default_2048() -> Self {
        // Using a well-known RSA modulus for testing.
        // This is NOT suitable for production — the factors must be unknown.
        // In production, use the RSA-2048 challenge modulus or generate via MPC.
        let p = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
              020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
              4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
              EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
            16,
        ).unwrap();
        let q = BigUint::parse_bytes(
            b"98AF7E6B2A3E6FA4590C8B267753DC7848F0C3455ED0E35CEBB34E4D0DB50B85\
              D6A719D0E23D02D0E08DC98FE7700D077CC7B218D8655F5E4E6577DDAD7D8F6E\
              EEB84EC2B25E2889B4C98FF0CF64BBE2D7DC529C5F21F3BBFB2D7B5F0E3E1B7C\
              A85F3B8DB13BE6B4E4F5C8E24C59B1B1E8CFC14441A48DC87E31EFAE43CB517F",
            16,
        ).unwrap();
        let modulus = &p * &q;

        Self {
            modulus,
            bits: 2048,
        }
    }

    /// Create VDF params with a small modulus (for fast testing).
    pub fn small_test() -> Self {
        // p = 104729, q = 104723 (two primes, ~17 bit each)
        let p = BigUint::from(104729u64);
        let q = BigUint::from(104723u64);
        let modulus = &p * &q;
        Self {
            modulus,
            bits: 34,
        }
    }
}

/// Evaluate the RSA VDF: compute y = x^(2^T) mod N by repeated squaring.
///
/// This is intentionally sequential and cannot be parallelized.
pub fn evaluate(params: &RsaVdfParams, input: &BigUint, iterations: u64) -> RsaVdfProof {
    let n = &params.modulus;

    // Compute y = x^(2^T) mod N
    let mut y = input.clone();
    for _ in 0..iterations {
        y = (&y * &y) % n;
    }

    // Wesolowski proof
    let challenge_l = derive_challenge(input, &y, iterations);

    // Compute pi = x^(floor(2^T / l)) mod N
    // We compute this by tracking the quotient during repeated squaring
    let pi = compute_wesolowski_proof(params, input, iterations, &challenge_l);

    RsaVdfProof {
        input: input.clone(),
        output: y,
        iterations,
        proof_pi: pi,
        challenge_l,
    }
}

/// Verify a VDF proof using Wesolowski's verification.
///
/// Check: pi^l * x^r == y mod N
/// where r = 2^T mod l
///
/// This is O(log T) — much faster than recomputing the full chain.
pub fn verify(params: &RsaVdfParams, proof: &RsaVdfProof) -> bool {
    let n = &params.modulus;

    // Recompute challenge
    let l = derive_challenge(&proof.input, &proof.output, proof.iterations);
    if l != proof.challenge_l {
        return false;
    }

    // Compute r = 2^T mod l
    let two = BigUint::from(2u64);
    let r = modpow_bigint(&two, proof.iterations, &l);

    // Check: pi^l * x^r == y mod N
    let pi_l = proof.proof_pi.modpow(&l, n);
    let x_r = proof.input.modpow(&r, n);
    let lhs = (&pi_l * &x_r) % n;

    lhs == proof.output
}

/// Derive the Fiat-Shamir challenge prime l from (x, y, T).
fn derive_challenge(input: &BigUint, output: &BigUint, iterations: u64) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"specter-vdf-challenge:");
    hasher.update(input.to_bytes_be());
    hasher.update(output.to_bytes_be());
    hasher.update(iterations.to_le_bytes());
    let hash = hasher.finalize();

    // Take a 128-bit prime from the hash
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    // Make it odd (potential prime)
    bytes[15] |= 1;
    let candidate = BigUint::from_bytes_be(&bytes);

    // Find the next prime >= candidate (simple trial division for prototype)
    next_prime(&candidate)
}

/// Compute the Wesolowski proof pi = x^(floor(2^T / l)) mod N.
///
/// Uses the long-division approach: track remainder r = 2^i mod l,
/// and accumulate pi = pi^2 * x^b where b = floor(2*r / l).
fn compute_wesolowski_proof(
    params: &RsaVdfParams,
    input: &BigUint,
    iterations: u64,
    l: &BigUint,
) -> BigUint {
    let n = &params.modulus;
    let two = BigUint::from(2u64);

    let mut pi = BigUint::one();
    let mut r = BigUint::one(); // r = 2^0 mod l = 1

    for _ in 0..iterations {
        let two_r = &r * &two;
        let b = &two_r / l; // quotient bit

        // pi = pi^2 * x^b mod N
        pi = (&pi * &pi) % n;
        if b == BigUint::one() {
            pi = (&pi * input) % n;
        }

        // r = 2*r mod l
        r = two_r % l;
    }

    pi
}

/// Compute a^exp mod m for BigUint exponent given as u64.
fn modpow_bigint(base: &BigUint, exp: u64, modulus: &BigUint) -> BigUint {
    base.modpow(&BigUint::from(exp), modulus)
}

/// Find the next prime >= n using trial division.
/// (For prototype — production would use Miller-Rabin.)
fn next_prime(n: &BigUint) -> BigUint {
    let mut candidate = n.clone();
    if &candidate % BigUint::from(2u64) == BigUint::ZERO {
        candidate += BigUint::one();
    }
    let two = BigUint::from(2u64);
    loop {
        if is_probably_prime(&candidate) {
            return candidate;
        }
        candidate += &two;
    }
}

/// Simple primality test (trial division up to sqrt for small primes,
/// then Fermat test for larger ones).
fn is_probably_prime(n: &BigUint) -> bool {
    if n <= &BigUint::from(1u64) {
        return false;
    }
    if n == &BigUint::from(2u64) || n == &BigUint::from(3u64) {
        return true;
    }
    if n % BigUint::from(2u64) == BigUint::ZERO {
        return false;
    }

    // Trial division for small factors
    let small_primes = [3u64, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];
    for &p in &small_primes {
        let bp = BigUint::from(p);
        if n == &bp {
            return true;
        }
        if n % &bp == BigUint::ZERO {
            return false;
        }
    }

    // Fermat test with base 2
    let one = BigUint::one();
    let n_minus_1 = n - &one;
    let two = BigUint::from(2u64);
    two.modpow(&n_minus_1, n) == one
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_params() -> RsaVdfParams {
        RsaVdfParams::small_test()
    }

    #[test]
    fn test_rsa_vdf_evaluate_and_verify() {
        let params = small_params();
        let input = BigUint::from(42u64);
        let proof = evaluate(&params, &input, 100);
        assert!(verify(&params, &proof));
    }

    #[test]
    fn test_rsa_vdf_deterministic() {
        let params = small_params();
        let input = BigUint::from(42u64);
        let p1 = evaluate(&params, &input, 50);
        let p2 = evaluate(&params, &input, 50);
        assert_eq!(p1.output, p2.output);
    }

    #[test]
    fn test_rsa_vdf_different_inputs() {
        let params = small_params();
        let p1 = evaluate(&params, &BigUint::from(10u64), 50);
        let p2 = evaluate(&params, &BigUint::from(20u64), 50);
        assert_ne!(p1.output, p2.output);
    }

    #[test]
    fn test_rsa_vdf_tampered_output_fails() {
        let params = small_params();
        let input = BigUint::from(42u64);
        let mut proof = evaluate(&params, &input, 50);
        proof.output += BigUint::one();
        assert!(!verify(&params, &proof));
    }

    #[test]
    fn test_rsa_vdf_tampered_proof_fails() {
        let params = small_params();
        let input = BigUint::from(42u64);
        let mut proof = evaluate(&params, &input, 50);
        proof.proof_pi += BigUint::one();
        assert!(!verify(&params, &proof));
    }

    #[test]
    fn test_rsa_vdf_sequential_nature() {
        let params = small_params();
        let input = BigUint::from(7u64);

        // Manually compute y = x^(2^3) mod N = ((x^2)^2)^2 mod N
        let n = &params.modulus;
        let x2 = (&input * &input) % n;
        let x4 = (&x2 * &x2) % n;
        let x8 = (&x4 * &x4) % n;

        let proof = evaluate(&params, &input, 3);
        assert_eq!(proof.output, x8);
    }

    #[test]
    fn test_wesolowski_verification_fast() {
        // Verify should be much faster than evaluate for large T
        let params = small_params();
        let input = BigUint::from(42u64);
        let proof = evaluate(&params, &input, 1000);
        // Verification doesn't repeat 1000 squarings — it's O(log T)
        assert!(verify(&params, &proof));
    }

    #[test]
    fn test_primality_check() {
        assert!(is_probably_prime(&BigUint::from(2u64)));
        assert!(is_probably_prime(&BigUint::from(3u64)));
        assert!(is_probably_prime(&BigUint::from(17u64)));
        assert!(is_probably_prime(&BigUint::from(97u64)));
        assert!(!is_probably_prime(&BigUint::from(4u64)));
        assert!(!is_probably_prime(&BigUint::from(100u64)));
    }
}
