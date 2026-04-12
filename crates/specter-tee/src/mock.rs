//! Mock attestation provider for local development.
//!
//! ⚠️ **DO NOT USE IN PRODUCTION** ⚠️ — this provider produces
//! unsigned "attestations" that are indistinguishable from fake, and
//! `verify_report` accepts any attestation whose `user_data` matches
//! the expected value. It exists solely so Windows / macOS / WSL
//! developers can exercise the trait-level code paths without an
//! AMD SEV-SNP host.
//!
//! Gated behind the `mock-attestation` feature which is NOT in the
//! default feature set.

#![cfg(feature = "mock-attestation")]

use crate::{Attestation, AttestationError, AttestationProvider, Platform, TcbPolicy};

/// A mock provider that produces unsigned attestations and
/// trivially "verifies" them. See module docs for safety warnings.
pub struct MockAttestationProvider;

impl MockAttestationProvider {
    /// Construct a new mock provider.
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockAttestationProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationProvider for MockAttestationProvider {
    fn request_report(&self, user_data: &[u8; 64]) -> Result<Attestation, AttestationError> {
        // Envelope format: domain tag + user_data, so a tampered
        // envelope fails the round-trip check.
        let mut report = Vec::with_capacity(32 + 64);
        report.extend_from_slice(b"specter-tee-mock-attestation:v1\0");
        report.extend_from_slice(user_data);
        Ok(Attestation {
            platform: Platform::None, // mock is explicitly "no platform"
            report,
            user_data: *user_data,
        })
    }

    fn verify_report(
        &self,
        attestation: &Attestation,
        expected_user_data: &[u8; 64],
        _policy: &TcbPolicy,
    ) -> Result<(), AttestationError> {
        if attestation.platform != Platform::None {
            return Err(AttestationError::VerifyError(
                "mock provider can only verify Platform::None attestations".into(),
            ));
        }
        if attestation.user_data != *expected_user_data {
            return Err(AttestationError::VerifyError(
                "user_data mismatch".into(),
            ));
        }
        if attestation.report.len() < 32 {
            return Err(AttestationError::VerifyError(
                "mock envelope too short".into(),
            ));
        }
        if &attestation.report[..32] != b"specter-tee-mock-attestation:v1\0" {
            return Err(AttestationError::VerifyError(
                "mock envelope magic mismatch".into(),
            ));
        }
        if &attestation.report[32..32 + 64] != expected_user_data {
            return Err(AttestationError::VerifyError(
                "mock envelope user_data mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{user_data_from_pubkey, TcbPolicy};

    #[test]
    fn mock_roundtrip() {
        let p = MockAttestationProvider::new();
        let user_data = user_data_from_pubkey(&[42u8; 32]);
        let attestation = p.request_report(&user_data).unwrap();
        p.verify_report(&attestation, &user_data, &TcbPolicy::permissive())
            .unwrap();
    }

    #[test]
    fn mock_rejects_mismatched_user_data() {
        let p = MockAttestationProvider::new();
        let u1 = user_data_from_pubkey(&[1u8; 32]);
        let u2 = user_data_from_pubkey(&[2u8; 32]);
        let attestation = p.request_report(&u1).unwrap();
        assert!(p
            .verify_report(&attestation, &u2, &TcbPolicy::permissive())
            .is_err());
    }

    #[test]
    fn mock_rejects_tampered_envelope() {
        let p = MockAttestationProvider::new();
        let user_data = user_data_from_pubkey(&[42u8; 32]);
        let mut attestation = p.request_report(&user_data).unwrap();
        attestation.report[0] ^= 0xFF;
        assert!(p
            .verify_report(&attestation, &user_data, &TcbPolicy::permissive())
            .is_err());
    }
}
