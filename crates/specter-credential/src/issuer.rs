//! Credential issuer — issues anonymous credentials over attribute commitments.
//!
//! The issuer verifies the holder's attributes (KYC, sanctions check, etc.)
//! and signs a Pedersen commitment to those attributes. The issuer knows the
//! attributes at issuance time but cannot link the credential to future uses.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};

use specter_primitives::pedersen::PedersenParams;
use specter_primitives::scalar_utils::random_scalar;

use crate::credential::{Attributes, Credential};

/// A credential issuer (KYC provider, government, etc.).
#[derive(Clone)]
pub struct Issuer {
    /// Issuer's secret signing key.
    secret: Scalar,
    /// Issuer's public verification key.
    pub public: RistrettoPoint,
    /// Pedersen parameters for attribute commitments.
    pub pedersen: PedersenParams,
}

impl Issuer {
    /// Create a new issuer with a random keypair.
    pub fn new() -> Self {
        let secret = random_scalar();
        let public = secret * G;
        Self {
            secret,
            public,
            pedersen: PedersenParams::new(),
        }
    }

    /// Issue a credential for the given attributes.
    ///
    /// The issuer:
    /// 1. Verifies the attributes (in production, this involves real KYC checks)
    /// 2. Creates a Pedersen commitment to the attribute vector
    /// 3. Signs the commitment with a Schnorr signature
    /// 4. Returns the credential to the holder
    pub fn issue(&self, attributes: &Attributes) -> Credential {
        let blinding = random_scalar();
        let commitment = self.pedersen.commit_vector(&attributes.to_scalars(), &blinding);

        // Sign the commitment with Schnorr
        let k = random_scalar();
        let r = k * G;

        let e = hash_credential_challenge(&r, &commitment, &self.public);
        let s = k + e * self.secret;

        Credential {
            commitment,
            blinding,
            attributes: attributes.clone(),
            signature_s: s,
            signature_e: e,
            issuer_pk: self.public,
        }
    }

    /// Verify a credential's signature (issuer-side check).
    pub fn verify_credential(&self, credential: &Credential) -> bool {
        verify_credential_signature(credential)
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a credential's Schnorr signature.
pub fn verify_credential_signature(credential: &Credential) -> bool {
    let r_prime = credential.signature_s * G - credential.signature_e * credential.issuer_pk;
    let expected_e = hash_credential_challenge(&r_prime, &credential.commitment, &credential.issuer_pk);
    expected_e == credential.signature_e
}

/// Hash function for credential challenge.
fn hash_credential_challenge(
    r: &RistrettoPoint,
    commitment: &RistrettoPoint,
    issuer_pk: &RistrettoPoint,
) -> Scalar {
    let hash = Sha512::new()
        .chain_update(b"specter-credential-sig:")
        .chain_update(r.compress().as_bytes())
        .chain_update(commitment.compress().as_bytes())
        .chain_update(issuer_pk.compress().as_bytes())
        .finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_attributes() -> Attributes {
        Attributes {
            kyc_passed: true,
            not_sanctioned: true,
            jurisdiction: "EU".to_string(),
            age_over_18: true,
        }
    }

    #[test]
    fn test_issue_and_verify() {
        let issuer = Issuer::new();
        let cred = issuer.issue(&test_attributes());
        assert!(verify_credential_signature(&cred));
    }

    #[test]
    fn test_different_attributes_valid() {
        let issuer = Issuer::new();

        let cred1 = issuer.issue(&Attributes {
            kyc_passed: true,
            not_sanctioned: true,
            jurisdiction: "US".to_string(),
            age_over_18: true,
        });
        let cred2 = issuer.issue(&Attributes {
            kyc_passed: true,
            not_sanctioned: true,
            jurisdiction: "BR".to_string(),
            age_over_18: false,
        });

        assert!(verify_credential_signature(&cred1));
        assert!(verify_credential_signature(&cred2));
        assert_ne!(cred1.commitment, cred2.commitment);
    }

    #[test]
    fn test_wrong_issuer_fails() {
        let issuer1 = Issuer::new();
        let issuer2 = Issuer::new();
        let mut cred = issuer1.issue(&test_attributes());

        // Swap issuer public key
        cred.issuer_pk = issuer2.public;
        assert!(!verify_credential_signature(&cred));
    }

    #[test]
    fn test_tampered_commitment_fails() {
        let issuer = Issuer::new();
        let mut cred = issuer.issue(&test_attributes());

        // Tamper with commitment
        cred.commitment = cred.commitment + G;
        assert!(!verify_credential_signature(&cred));
    }

    #[test]
    fn test_many_credentials() {
        let issuer = Issuer::new();
        for _ in 0..20 {
            let cred = issuer.issue(&test_attributes());
            assert!(verify_credential_signature(&cred));
        }
    }
}
