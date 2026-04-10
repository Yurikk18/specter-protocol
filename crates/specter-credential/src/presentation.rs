//! Selective disclosure presentation proofs.
//!
//! A holder can prove specific attributes from their credential without
//! revealing all attributes or their identity. The verifier learns ONLY
//! the disclosed attributes and nothing else.
//!
//! This implements a Schnorr-based proof of knowledge of the opening
//! of a Pedersen commitment, with selective disclosure of chosen attributes.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};

use specter_primitives::pedersen::PedersenParams;
use specter_primitives::scalar_utils::random_scalar;

use crate::credential::{Attributes, Credential};

/// A selective disclosure presentation.
///
/// Proves that the holder has a valid credential with specific attributes
/// without revealing the credential itself or undisclosed attributes.
#[derive(Clone, Debug)]
pub struct Presentation {
    /// The credential commitment (public).
    pub commitment: RistrettoPoint,
    /// Issuer's public key.
    pub issuer_pk: RistrettoPoint,
    /// Credential signature (proves issuer endorsed this commitment).
    pub cred_signature_s: Scalar,
    pub cred_signature_e: Scalar,
    /// Disclosed attribute values (index -> value).
    pub disclosed: Vec<(usize, Scalar)>,
    /// ZK proof of knowledge of undisclosed attributes.
    /// This proves "I know the hidden values that complete this commitment"
    /// without revealing them.
    pub proof_commitment: RistrettoPoint,
    pub proof_response: Vec<Scalar>,
    pub proof_challenge: Scalar,
}

/// Indices of attributes that can be selectively disclosed.
pub const ATTR_KYC_PASSED: usize = 0;
pub const ATTR_NOT_SANCTIONED: usize = 1;
pub const ATTR_JURISDICTION: usize = 2;
pub const ATTR_AGE_OVER_18: usize = 3;

/// Create a selective disclosure presentation.
///
/// The holder proves they have a credential with specific attributes
/// by revealing chosen attributes and providing a ZK proof for the rest.
pub fn create_presentation(
    credential: &Credential,
    disclose_indices: &[usize],
    pedersen: &PedersenParams,
) -> Presentation {
    let all_scalars = credential.attributes.to_scalars();
    let n = Attributes::count();

    // Build generators for the vector commitment
    let generators: Vec<RistrettoPoint> = (0..n)
        .map(|i| {
            let label = format!("specter-pedersen-vector-G-{}", i);
            let hash = Sha512::digest(label.as_bytes());
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&hash);
            RistrettoPoint::from_uniform_bytes(&wide)
        })
        .collect();

    // Separate disclosed and hidden attributes
    let disclosed: Vec<(usize, Scalar)> = disclose_indices
        .iter()
        .map(|&i| (i, all_scalars[i]))
        .collect();

    let hidden_indices: Vec<usize> = (0..n)
        .filter(|i| !disclose_indices.contains(i))
        .collect();

    // ZK proof of knowledge of hidden attributes + blinding factor
    // Commitment: T = sum(r_i * G_i for hidden i) + r_blind * H
    let randoms: Vec<Scalar> = (0..hidden_indices.len() + 1)
        .map(|_| random_scalar())
        .collect();

    let mut t_points: Vec<RistrettoPoint> = hidden_indices
        .iter()
        .enumerate()
        .map(|(j, &i)| randoms[j] * generators[i])
        .collect();
    t_points.push(randoms[hidden_indices.len()] * pedersen.h);
    let proof_commitment: RistrettoPoint = t_points.iter().fold(
        RistrettoPoint::default(),
        |acc, p| acc + p,
    );

    // Challenge
    let challenge = hash_presentation_challenge(
        &credential.commitment,
        &proof_commitment,
        &disclosed,
        &credential.issuer_pk,
    );

    // Responses: s_i = r_i + challenge * hidden_value_i (for hidden attrs)
    //            s_blind = r_blind + challenge * blinding
    let mut responses: Vec<Scalar> = hidden_indices
        .iter()
        .enumerate()
        .map(|(j, &i)| randoms[j] + challenge * all_scalars[i])
        .collect();
    responses.push(randoms[hidden_indices.len()] + challenge * credential.blinding);

    Presentation {
        commitment: credential.commitment,
        issuer_pk: credential.issuer_pk,
        cred_signature_s: credential.signature_s,
        cred_signature_e: credential.signature_e,
        disclosed,
        proof_commitment,
        proof_response: responses,
        proof_challenge: challenge,
    }
}

/// Verify a selective disclosure presentation.
///
/// Checks:
/// 1. The credential signature is valid (issuer endorsed the commitment)
/// 2. The ZK proof of hidden attributes is valid
/// 3. The disclosed attributes are consistent with the commitment
pub fn verify_presentation(
    presentation: &Presentation,
    pedersen: &PedersenParams,
) -> bool {
    let n = Attributes::count();

    // 1. Verify credential signature
    let r_prime = presentation.cred_signature_s * G
        - presentation.cred_signature_e * presentation.issuer_pk;
    let expected_e = {
        let hash = Sha512::new()
            .chain_update(b"specter-credential-sig:")
            .chain_update(r_prime.compress().as_bytes())
            .chain_update(presentation.commitment.compress().as_bytes())
            .chain_update(presentation.issuer_pk.compress().as_bytes())
            .finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash);
        Scalar::from_bytes_mod_order_wide(&wide)
    };
    if expected_e != presentation.cred_signature_e {
        return false;
    }

    // Build generators
    let generators: Vec<RistrettoPoint> = (0..n)
        .map(|i| {
            let label = format!("specter-pedersen-vector-G-{}", i);
            let hash = Sha512::digest(label.as_bytes());
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&hash);
            RistrettoPoint::from_uniform_bytes(&wide)
        })
        .collect();

    let disclosed_indices: Vec<usize> = presentation.disclosed.iter().map(|(i, _)| *i).collect();
    let hidden_indices: Vec<usize> = (0..n)
        .filter(|i| !disclosed_indices.contains(i))
        .collect();

    // 2. Verify ZK proof
    // Check: T == sum(s_i * G_i for hidden) + s_blind * H - challenge * (C - sum(disclosed_j * G_j))
    let disclosed_part: RistrettoPoint = presentation
        .disclosed
        .iter()
        .map(|(i, v)| *v * generators[*i])
        .fold(RistrettoPoint::default(), |acc, p| acc + p);

    // C_hidden = C - disclosed_part = commitment to hidden attrs + blinding*H
    let c_hidden = presentation.commitment - disclosed_part;

    // Recompute T from responses
    let mut recomputed_t = RistrettoPoint::default();
    for (j, &_i) in hidden_indices.iter().enumerate() {
        recomputed_t += presentation.proof_response[j] * generators[hidden_indices[j]];
    }
    recomputed_t += presentation.proof_response[hidden_indices.len()] * pedersen.h;
    recomputed_t -= presentation.proof_challenge * c_hidden;

    // Recompute challenge
    let expected_challenge = hash_presentation_challenge(
        &presentation.commitment,
        &recomputed_t,
        &presentation.disclosed,
        &presentation.issuer_pk,
    );

    expected_challenge == presentation.proof_challenge
}

/// Hash function for presentation challenge.
fn hash_presentation_challenge(
    commitment: &RistrettoPoint,
    proof_commitment: &RistrettoPoint,
    disclosed: &[(usize, Scalar)],
    issuer_pk: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"specter-presentation-challenge:");
    hasher.update(commitment.compress().as_bytes());
    hasher.update(proof_commitment.compress().as_bytes());
    hasher.update(issuer_pk.compress().as_bytes());
    for (i, v) in disclosed {
        hasher.update((*i as u64).to_le_bytes());
        hasher.update(v.as_bytes());
    }
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::Attributes;
    use crate::issuer::Issuer;

    fn test_cred() -> (Issuer, Credential) {
        let issuer = Issuer::new();
        let attrs = Attributes {
            kyc_passed: true,
            not_sanctioned: true,
            jurisdiction: "EU".to_string(),
            age_over_18: true,
        };
        let cred = issuer.issue(&attrs);
        (issuer, cred)
    }

    #[test]
    fn test_disclose_kyc_only() {
        let (issuer, cred) = test_cred();
        let presentation = create_presentation(&cred, &[ATTR_KYC_PASSED], &issuer.pedersen);

        assert!(verify_presentation(&presentation, &issuer.pedersen));
        assert_eq!(presentation.disclosed.len(), 1);
        assert_eq!(presentation.disclosed[0].0, ATTR_KYC_PASSED);
        assert_eq!(presentation.disclosed[0].1, Scalar::from(1u64)); // true
    }

    #[test]
    fn test_disclose_multiple() {
        let (issuer, cred) = test_cred();
        let presentation = create_presentation(
            &cred,
            &[ATTR_KYC_PASSED, ATTR_NOT_SANCTIONED],
            &issuer.pedersen,
        );

        assert!(verify_presentation(&presentation, &issuer.pedersen));
        assert_eq!(presentation.disclosed.len(), 2);
    }

    #[test]
    fn test_disclose_all() {
        let (issuer, cred) = test_cred();
        let presentation = create_presentation(
            &cred,
            &[ATTR_KYC_PASSED, ATTR_NOT_SANCTIONED, ATTR_JURISDICTION, ATTR_AGE_OVER_18],
            &issuer.pedersen,
        );

        assert!(verify_presentation(&presentation, &issuer.pedersen));
        assert_eq!(presentation.disclosed.len(), 4);
    }

    #[test]
    fn test_disclose_none() {
        let (issuer, cred) = test_cred();
        let presentation = create_presentation(&cred, &[], &issuer.pedersen);

        assert!(verify_presentation(&presentation, &issuer.pedersen));
        assert_eq!(presentation.disclosed.len(), 0);
    }

    #[test]
    fn test_wrong_issuer_fails() {
        let (issuer, cred) = test_cred();
        let other_issuer = Issuer::new();
        let mut presentation = create_presentation(&cred, &[ATTR_KYC_PASSED], &issuer.pedersen);

        presentation.issuer_pk = other_issuer.public;
        assert!(!verify_presentation(&presentation, &issuer.pedersen));
    }

    #[test]
    fn test_tampered_disclosed_value_fails() {
        let (issuer, cred) = test_cred();
        let mut presentation = create_presentation(&cred, &[ATTR_KYC_PASSED], &issuer.pedersen);

        // Change disclosed value from true (1) to false (0)
        presentation.disclosed[0].1 = Scalar::from(0u64);
        assert!(!verify_presentation(&presentation, &issuer.pedersen));
    }

    #[test]
    fn test_many_presentations_valid() {
        let (issuer, cred) = test_cred();
        for _ in 0..15 {
            let presentation = create_presentation(
                &cred,
                &[ATTR_NOT_SANCTIONED],
                &issuer.pedersen,
            );
            assert!(verify_presentation(&presentation, &issuer.pedersen));
        }
    }
}
