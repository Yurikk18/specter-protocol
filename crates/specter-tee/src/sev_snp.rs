//! AMD SEV-SNP guest attestation **request** backend. Linux-only.
//!
//! This module handles the hardware interaction with `/dev/sev-guest`
//! to obtain attestation reports. Verification is handled by the
//! platform-independent [`crate::sev_snp_verify`] module.
//!
//! Only compiled on `target_os = "linux"` with the `sev-snp` feature.

#![cfg(all(target_os = "linux", feature = "sev-snp"))]

use crate::{Attestation, AttestationError, AttestationProvider, Platform, TcbPolicy};
use crate::sev_snp_verify::SnpWire;

/// Runtime detection of a SEV-SNP guest via `/dev/sev-guest`.
pub fn is_sev_snp_guest() -> bool {
    std::path::Path::new("/dev/sev-guest").exists()
}

/// SEV-SNP attestation provider backed by virtee/sev.
pub struct SevSnpProvider;

impl SevSnpProvider {
    /// Construct a new SEV-SNP provider. Fails if `/dev/sev-guest`
    /// is not present.
    pub fn new() -> Result<Self, AttestationError> {
        if !is_sev_snp_guest() {
            return Err(AttestationError::SnpDeviceError(
                "/dev/sev-guest not present — not running inside a SEV-SNP VM".into(),
            ));
        }
        Ok(Self)
    }
}

impl AttestationProvider for SevSnpProvider {
    fn request_report(&self, user_data: &[u8; 64]) -> Result<Attestation, AttestationError> {
        use sev::firmware::guest::Firmware;

        let mut fw = Firmware::open()
            .map_err(|e| AttestationError::SnpDeviceError(format!("{e:?}")))?;

        let (report_bytes, cert_table) = fw
            .get_ext_report(Some(1), Some(*user_data), Some(0))
            .map_err(|e| AttestationError::SnpReportError(format!("{e:?}")))?;

        let wire = SnpWire {
            report_bytes,
            cert_table: cert_table.map(serialize_cert_table),
        };
        let bytes = bincode::serialize(&wire)
            .map_err(|e| AttestationError::SnpReportError(format!("serialize: {e:?}")))?;

        Ok(Attestation {
            platform: Platform::SevSnp,
            report: bytes,
            user_data: *user_data,
        })
    }

    fn verify_report(
        &self,
        attestation: &Attestation,
        expected_user_data: &[u8; 64],
        policy: &TcbPolicy,
    ) -> Result<(), AttestationError> {
        // Delegate to the portable verification module.
        crate::sev_snp_verify::verify_snp_report(attestation, expected_user_data, policy)
    }
}

/// Serialize a `CertTableEntry` slice to portable (guid, bytes) pairs.
fn serialize_cert_table(
    table: Vec<sev::firmware::host::CertTableEntry>,
) -> Vec<(String, Vec<u8>)> {
    table
        .into_iter()
        .map(|e| {
            let guid = match e.cert_type {
                sev::firmware::host::CertType::ARK => "ark".to_string(),
                sev::firmware::host::CertType::ASK => "ask".to_string(),
                sev::firmware::host::CertType::VCEK => "vcek".to_string(),
                sev::firmware::host::CertType::VLEK => "vlek".to_string(),
                sev::firmware::host::CertType::CRL => "crl".to_string(),
                sev::firmware::host::CertType::OTHER(uuid) => format!("other:{uuid}"),
                sev::firmware::host::CertType::Empty => "empty".to_string(),
            };
            (guid, e.data.clone())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sev_snp_provider_fails_without_device() {
        if !is_sev_snp_guest() {
            assert!(SevSnpProvider::new().is_err());
        }
    }
}
