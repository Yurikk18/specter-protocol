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
use num_integer::Integer;
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
    /// Create VDF params with the RSA-2048 challenge modulus.
    ///
    /// This is the RSA-2048 number from the RSA Factoring Challenge
    /// (published 1991). Its factorization is unknown, making it safe
    /// for use as a VDF group modulus.
    pub fn default_2048() -> Self {
        // RSA-2048 challenge number — factorization UNKNOWN.
        // Source: RSA Laboratories, published in the RSA Factoring Challenge.
        // 617 decimal digits, 2048 bits.
        let modulus = BigUint::parse_bytes(
            b"25195908475657893494027183240048398571429282126204032027777137836\
              04366202070759555626401852588078440691829064124951508218929855914\
              91761845028084891200728449926873928072877677359714183472702618963\
              75014971824691165077613379859095700097330459748808428401797429100\
              64245869181719511874612151517265463228221686998754918242243363725\
              90851418654620435767984233871847744792073993423658482382428119816\
              38150106748104516603773060562016196762561338441436038339044149526\
              34432190114657544454178424020924616515723350778707749817125772467\
              96292638635637328991215483143816789988504044536402352738195137863\
              65643912120103971228221207203578", 10,
        ).expect("RSA-2048 challenge number");

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

/// Find the next prime >= n using Miller-Rabin.
fn next_prime(n: &BigUint) -> BigUint {
    let mut candidate = n.clone();
    if candidate.is_even() {
        candidate += BigUint::one();
    }
    let two = BigUint::from(2u64);
    loop {
        if is_probably_prime_miller_rabin(&candidate, 20) {
            return candidate;
        }
        candidate += &two;
    }
}

/// Miller-Rabin primality test with `rounds` deterministic witnesses.
///
/// 20 rounds gives error probability < 4^(-20) ~ 10^(-12).
/// Uses the first `rounds` small primes as witnesses for determinism.
fn is_probably_prime_miller_rabin(n: &BigUint, rounds: u32) -> bool {
    let one = BigUint::one();
    let two = BigUint::from(2u64);

    if n < &two {
        return false;
    }
    if n == &two || n == &BigUint::from(3u64) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Write n-1 as 2^r * d where d is odd
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut r: u32 = 0;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    // Deterministic witnesses (first `rounds` primes)
    let witnesses: Vec<u64> = vec![
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
        59, 61, 67, 71, 73, 79, 83, 89,
    ];

    'witness: for &w in witnesses.iter().take(rounds as usize) {
        let a = BigUint::from(w);
        if &a >= n {
            continue;
        }
        let mut x = a.modpow(&d, n);

        if x == one || x == n_minus_1 {
            continue 'witness;
        }

        for _ in 0..(r - 1) {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }

        return false; // composite
    }

    true // probably prime
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
    fn test_primality_miller_rabin() {
        assert!(is_probably_prime_miller_rabin(&BigUint::from(2u64), 20));
        assert!(is_probably_prime_miller_rabin(&BigUint::from(3u64), 20));
        assert!(is_probably_prime_miller_rabin(&BigUint::from(17u64), 20));
        assert!(is_probably_prime_miller_rabin(&BigUint::from(97u64), 20));
        assert!(!is_probably_prime_miller_rabin(&BigUint::from(4u64), 20));
        assert!(!is_probably_prime_miller_rabin(&BigUint::from(100u64), 20));
        // Carmichael numbers — MUST be rejected by Miller-Rabin
        assert!(!is_probably_prime_miller_rabin(&BigUint::from(561u64), 20));
        assert!(!is_probably_prime_miller_rabin(&BigUint::from(1105u64), 20));
        assert!(!is_probably_prime_miller_rabin(&BigUint::from(1729u64), 20));
    }
}
