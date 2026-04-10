//! Credential revocation and expiry checking.
//!
//! Credentials can be revoked (KYC lost, sanctioned) or expired
//! (time-limited compliance attestation). The RevocationList tracks
//! revoked credential commitment hashes.

use std::collections::HashSet;
use curve25519_dalek::RistrettoPoint;

use crate::credential::Credential;

/// A list of revoked credential commitments.
pub struct RevocationList {
    /// Set of revoked credential commitment hashes (compressed point bytes).
    revoked: HashSet<[u8; 32]>,
}

impl RevocationList {
    /// Create an empty revocation list.
    pub fn new() -> Self {
        Self {
            revoked: HashSet::new(),
        }
    }

    /// Revoke a credential by its commitment.
    pub fn revoke(&mut self, credential: &Credential) {
        let hash = commitment_hash(&credential.commitment);
        self.revoked.insert(hash);
    }

    /// Check if a credential has been revoked.
    pub fn is_revoked(&self, credential: &Credential) -> bool {
        let hash = commitment_hash(&credential.commitment);
        self.revoked.contains(&hash)
    }

    /// Number of revoked credentials.
    pub fn count(&self) -> usize {
        self.revoked.len()
    }
}

impl Default for RevocationList {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a credential has expired based on current time.
///
/// Returns true if the credential's `expires_at` is non-zero and
/// less than `current_time` (Unix timestamp).
pub fn is_expired(credential: &Credential, current_time: u64) -> bool {
    credential.attributes.expires_at > 0 && current_time > credential.attributes.expires_at
}

fn commitment_hash(commitment: &RistrettoPoint) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(commitment.compress().as_bytes());
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::Attributes;
    use crate::issuer::Issuer;

    fn test_issuer() -> Issuer {
        Issuer::new()
    }

    fn test_attrs(expires_at: u64) -> Attributes {
        Attributes {
            kyc_passed: true,
            not_sanctioned: true,
            jurisdiction: "EU".to_string(),
            age_over_18: true,
            expires_at,
        }
    }

    #[test]
    fn test_revoke_and_check() {
        let issuer = test_issuer();
        let cred = issuer.issue(&test_attrs(0));

        let mut list = RevocationList::new();
        assert!(!list.is_revoked(&cred));

        list.revoke(&cred);
        assert!(list.is_revoked(&cred));
    }

    #[test]
    fn test_different_credential_not_revoked() {
        let issuer = test_issuer();
        let cred1 = issuer.issue(&test_attrs(0));
        let cred2 = issuer.issue(&test_attrs(0));

        let mut list = RevocationList::new();
        list.revoke(&cred1);

        assert!(list.is_revoked(&cred1));
        assert!(!list.is_revoked(&cred2));
    }

    #[test]
    fn test_expiry_no_expiry() {
        let issuer = test_issuer();
        let cred = issuer.issue(&test_attrs(0)); // expires_at = 0 means no expiry
        assert!(!is_expired(&cred, 999999999));
    }

    #[test]
    fn test_expiry_not_yet_expired() {
        let issuer = test_issuer();
        let cred = issuer.issue(&test_attrs(1000));
        assert!(!is_expired(&cred, 500)); // current time before expiry
    }

    #[test]
    fn test_expiry_expired() {
        let issuer = test_issuer();
        let cred = issuer.issue(&test_attrs(1000));
        assert!(is_expired(&cred, 1001)); // current time after expiry
    }

    #[test]
    fn test_revocation_list_count() {
        let issuer = test_issuer();
        let mut list = RevocationList::new();

        for _ in 0..5 {
            let cred = issuer.issue(&test_attrs(0));
            list.revoke(&cred);
        }

        assert_eq!(list.count(), 5);
    }
}
