//! Anonymous credential types.
//!
//! A credential attests to a set of attributes (KYC status, jurisdiction, etc.)
//! without revealing the holder's identity. The credential is a Schnorr-based
//! signature over Pedersen commitments to the attribute values.

use curve25519_dalek::{RistrettoPoint, Scalar};

/// A set of compliance attributes that can be attested.
#[derive(Clone, Debug)]
pub struct Attributes {
    /// Whether the holder has passed KYC verification.
    pub kyc_passed: bool,
    /// Whether the holder is NOT on a sanctions list.
    pub not_sanctioned: bool,
    /// Jurisdiction code (e.g., "EU", "US", "BR").
    pub jurisdiction: String,
    /// Whether the holder is over 18.
    pub age_over_18: bool,
    /// Credential expiry timestamp (Unix seconds). 0 = no expiry.
    pub expires_at: u64,
}

impl Attributes {
    /// Encode attributes as scalar values for commitment.
    pub fn to_scalars(&self) -> Vec<Scalar> {
        vec![
            Scalar::from(self.kyc_passed as u64),
            Scalar::from(self.not_sanctioned as u64),
            Scalar::from(self.jurisdiction_code()),
            Scalar::from(self.age_over_18 as u64),
        ]
    }

    /// Map jurisdiction string to a numeric code.
    fn jurisdiction_code(&self) -> u64 {
        match self.jurisdiction.as_str() {
            "EU" => 1,
            "US" => 2,
            "BR" => 3,
            "UK" => 4,
            "CH" => 5,
            "JP" => 6,
            _ => 99,
        }
    }

    /// Number of attributes.
    pub fn count() -> usize {
        4
    }
}

/// An anonymous credential - a signed set of attribute commitments.
#[derive(Clone, Debug)]
pub struct Credential {
    /// Pedersen commitment to the attribute vector.
    pub commitment: RistrettoPoint,
    /// Blinding factor used in the commitment.
    pub blinding: Scalar,
    /// The actual attribute values (known to the holder, hidden from verifiers).
    pub attributes: Attributes,
    /// Issuer's signature over the commitment.
    pub signature_s: Scalar,
    pub signature_e: Scalar,
    /// Issuer's public key.
    pub issuer_pk: RistrettoPoint,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attributes_to_scalars() {
        let attrs = Attributes {
            kyc_passed: true,
            not_sanctioned: true,
            jurisdiction: "EU".to_string(),
            age_over_18: true,
            expires_at: 0,
        };
        let scalars = attrs.to_scalars();
        assert_eq!(scalars.len(), 4);
        assert_eq!(scalars[0], Scalar::from(1u64)); // kyc = true
        assert_eq!(scalars[2], Scalar::from(1u64)); // EU = 1
    }
}
