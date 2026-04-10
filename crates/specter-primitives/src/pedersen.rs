use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};

/// Parameters for the Pedersen commitment scheme over Ristretto255.
///
/// Uses two independent generators G and H, derived via "nothing up my sleeve"
/// hashing of distinct byte strings, ensuring no party knows the discrete log
/// relationship between them.
#[derive(Clone, Debug)]
pub struct PedersenParams {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
}

impl PedersenParams {
    /// Create new parameters with independently derived generators.
    pub fn new() -> Self {
        let g = Self::hash_to_point(b"specter-pedersen-generator-G");
        let h = Self::hash_to_point(b"specter-pedersen-generator-H");
        Self { g, h }
    }

    /// Hash a label to a Ristretto point using SHA-512.
    fn hash_to_point(label: &[u8]) -> RistrettoPoint {
        let hash = Sha512::digest(label);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash);
        RistrettoPoint::from_uniform_bytes(&wide)
    }

    /// Compute a Pedersen commitment: C = value * G + blinding * H.
    ///
    /// The commitment hides the value (via the random blinding factor)
    /// and is binding (the committer cannot change the value later).
    ///
    /// ```
    /// use specter_primitives::pedersen::PedersenParams;
    /// use specter_primitives::scalar_utils::{scalar_from_u64, random_scalar};
    ///
    /// let params = PedersenParams::new();
    /// let value = scalar_from_u64(100);
    /// let blinding = random_scalar();
    /// let c = params.commit(&value, &blinding);
    ///
    /// // Commitment is binding: can verify with the same inputs
    /// assert!(params.verify_opening(&c, &value, &blinding));
    /// // But fails with wrong value
    /// assert!(!params.verify_opening(&c, &scalar_from_u64(999), &blinding));
    /// ```
    pub fn commit(&self, value: &Scalar, blinding: &Scalar) -> RistrettoPoint {
        RistrettoPoint::multiscalar_mul(&[*value, *blinding], &[self.g, self.h])
    }

    /// Verify that a commitment opens to the given value and blinding factor.
    pub fn verify_opening(
        &self,
        commitment: &RistrettoPoint,
        value: &Scalar,
        blinding: &Scalar,
    ) -> bool {
        let expected = self.commit(value, blinding);
        commitment == &expected
    }

    /// Compute a Pedersen vector commitment: C = sum(values[i] * G_i) + blinding * H.
    ///
    /// Uses the base generator G hashed with the index to produce independent
    /// generators for each position.
    pub fn commit_vector(&self, values: &[Scalar], blinding: &Scalar) -> RistrettoPoint {
        let generators: Vec<RistrettoPoint> = (0..values.len())
            .map(|i| {
                let label = format!("specter-pedersen-vector-G-{}", i);
                Self::hash_to_point(label.as_bytes())
            })
            .collect();

        let mut scalars: Vec<Scalar> = values.to_vec();
        scalars.push(*blinding);

        let mut points: Vec<RistrettoPoint> = generators;
        points.push(self.h);

        RistrettoPoint::multiscalar_mul(&scalars, &points)
    }

    /// Create a ZK proof that a commitment contains a specific value,
    /// WITHOUT revealing the blinding factor.
    ///
    /// Proves knowledge of r such that C = v*G + r*H.
    pub fn prove_value(&self, _value: &Scalar, blinding: &Scalar) -> ValueProof {
        let t = crate::scalar_utils::random_scalar();
        let t_commit = t * self.h;

        let challenge = value_proof_challenge(&self.h, &(*blinding * self.h), &t_commit);
        let response = t + challenge * blinding;

        ValueProof {
            commitment: t_commit,
            response,
        }
    }

    /// Verify a ZK proof that a commitment contains a claimed value.
    pub fn verify_value_proof(
        &self,
        token_commitment: &RistrettoPoint,
        claimed_value: &Scalar,
        proof: &ValueProof,
    ) -> bool {
        let c_minus_vg = token_commitment - claimed_value * self.g;
        let challenge = value_proof_challenge(&self.h, &c_minus_vg, &proof.commitment);
        let lhs = proof.response * self.h;
        let rhs = proof.commitment + challenge * c_minus_vg;
        lhs == rhs
    }
}

/// ZK proof that a Pedersen commitment opens to a specific value
/// without revealing the blinding factor.
#[derive(Clone, Debug)]
pub struct ValueProof {
    pub commitment: RistrettoPoint,
    pub response: Scalar,
}

fn value_proof_challenge(
    h: &RistrettoPoint,
    statement: &RistrettoPoint,
    nonce: &RistrettoPoint,
) -> Scalar {
    use sha2::{Digest, Sha512};
    let hash = Sha512::new()
        .chain_update(b"specter-value-proof:")
        .chain_update(h.compress().as_bytes())
        .chain_update(statement.compress().as_bytes())
        .chain_update(nonce.compress().as_bytes())
        .finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

impl Default for PedersenParams {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar_utils::{random_scalar, scalar_from_u64};

    #[test]
    fn test_commitment_roundtrip() {
        let params = PedersenParams::new();
        let value = scalar_from_u64(100);
        let blinding = random_scalar();
        let commitment = params.commit(&value, &blinding);
        assert!(params.verify_opening(&commitment, &value, &blinding));
    }

    #[test]
    fn test_wrong_opening_fails() {
        let params = PedersenParams::new();
        let value = scalar_from_u64(100);
        let blinding = random_scalar();
        let commitment = params.commit(&value, &blinding);

        let wrong_value = scalar_from_u64(999);
        assert!(!params.verify_opening(&commitment, &wrong_value, &blinding));

        let wrong_blinding = random_scalar();
        assert!(!params.verify_opening(&commitment, &value, &wrong_blinding));
    }

    #[test]
    fn test_homomorphic_addition() {
        let params = PedersenParams::new();

        let a = scalar_from_u64(30);
        let r1 = random_scalar();
        let ca = params.commit(&a, &r1);

        let b = scalar_from_u64(70);
        let r2 = random_scalar();
        let cb = params.commit(&b, &r2);

        let sum_commit = ca + cb;
        let expected = params.commit(&(a + b), &(r1 + r2));

        assert_eq!(sum_commit, expected);
    }

    #[test]
    fn test_different_values_different_commitments() {
        let params = PedersenParams::new();
        let blinding = random_scalar();
        let c1 = params.commit(&scalar_from_u64(10), &blinding);
        let c2 = params.commit(&scalar_from_u64(20), &blinding);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_vector_commitment() {
        let params = PedersenParams::new();
        let values = vec![scalar_from_u64(1), scalar_from_u64(2), scalar_from_u64(3)];
        let blinding = random_scalar();
        let c = params.commit_vector(&values, &blinding);

        // Same inputs produce same commitment
        let c2 = params.commit_vector(&values, &blinding);
        assert_eq!(c, c2);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_pedersen_homomorphic(
            a_val in 0u64..1_000_000,
            b_val in 0u64..1_000_000,
        ) {
            let params = PedersenParams::new();
            let a = scalar_from_u64(a_val);
            let b = scalar_from_u64(b_val);
            let r1 = random_scalar();
            let r2 = random_scalar();

            let sum_commit = params.commit(&a, &r1) + params.commit(&b, &r2);
            let direct = params.commit(&(a + b), &(r1 + r2));
            prop_assert_eq!(sum_commit.compress(), direct.compress());
        }
    }

    #[test]
    fn test_homomorphic_many_values() {
        let params = PedersenParams::new();
        for i in 0..50 {
            let a = scalar_from_u64(i * 7 + 1);
            let b = scalar_from_u64(i * 13 + 3);
            let r1 = random_scalar();
            let r2 = random_scalar();

            let sum_commit = params.commit(&a, &r1) + params.commit(&b, &r2);
            let direct = params.commit(&(a + b), &(r1 + r2));
            assert_eq!(sum_commit, direct, "failed at i={}", i);
        }
    }
}
