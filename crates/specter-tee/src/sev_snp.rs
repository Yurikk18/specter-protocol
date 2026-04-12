//! AMD SEV-SNP guest attestation backend.
//!
//! Wraps the [`sev`](https://crates.io/crates/sev) crate (pinned to
//! `=6.3.1` with the pure-Rust `crypto_nossl` backend) so that
//! Specter validators running inside a confidential VM can request
//! attestation reports and bind them to their mint public key.
//!
//! The design follows the guidance in §7 of the AMD SEV-SNP ABI
//! specification and §4 of the Cloud Confidential Computing Reference
//! Architecture (Oct 2023):
//!
//! 1. `get_ext_report` — request the report **and** the host-cached
//!    certificate table (ARK/ASK/VCEK) in one ioctl. This avoids a
//!    round-trip to AMD KDS at runtime, which is a liveness risk and
//!    leaks timing metadata.
//! 2. `AttestationReport::from_bytes` — parse the 0x4A0-byte report
//!    following the SNP ABI layout.
//! 3. `Chain::verify()` — validate ARK self-sig → ARK→ASK → ASK→VCEK.
//! 4. `(&chain, &report).verify()` — validate the VCEK signature over
//!    the report body (ECDSA-P384).
//!
//! Only compiled on `target_os = "linux"` with the `sev-snp` feature.

#![cfg(all(target_os = "linux", feature = "sev-snp"))]

use crate::{Attestation, AttestationError, AttestationProvider, Platform};

/// Runtime detection of a SEV-SNP guest via the presence of
/// `/dev/sev-guest`. Returns `false` if the device does not exist or
/// is unreadable.
pub fn is_sev_snp_guest() -> bool {
    std::path::Path::new("/dev/sev-guest").exists()
}

/// SEV-SNP attestation provider backed by virtee/sev.
pub struct SevSnpProvider;

impl SevSnpProvider {
    /// Construct a new SEV-SNP provider. Fails if `/dev/sev-guest`
    /// is not present (i.e., we are not inside a confidential VM).
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

        // `get_ext_report` returns (report_bytes, Option<cert_table>).
        // We request the report under VMPL=0 (most privileged guest
        // context; the measurement field then reflects the guest
        // launch digest with no chained trust). Message version 1 is
        // the current stable protocol.
        let (report_bytes, cert_table) = fw
            .get_ext_report(Some(1), Some(*user_data), Some(0))
            .map_err(|e| AttestationError::SnpReportError(format!("{e:?}")))?;

        // Serialize both the raw report and the cert table together
        // so `verify_report` is self-contained. bincode is used as a
        // simple length-delimited framing — not a wire format for
        // external peers; those should speak the native SNP ABI.
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
    ) -> Result<(), AttestationError> {
        use sev::certs::snp::{ca, Certificate, Chain, Verifiable};
        use sev::firmware::guest::AttestationReport;

        if attestation.platform != Platform::SevSnp {
            return Err(AttestationError::VerifyError(
                "attestation is not from SEV-SNP".into(),
            ));
        }
        if attestation.user_data != *expected_user_data {
            return Err(AttestationError::VerifyError(
                "user_data mismatch between attestation and expected".into(),
            ));
        }

        // Bound the deserialization. An SNP report is 0x4A0 bytes
        // (~1184 bytes) plus the cert table which is typically <16
        // KiB. 1 MiB is a very generous ceiling that still prevents
        // an attacker from triggering unbounded allocation via a
        // forged `Vec<u8>` length prefix.
        const MAX_ENVELOPE_BYTES: usize = 1 << 20;
        if attestation.report.len() > MAX_ENVELOPE_BYTES {
            return Err(AttestationError::VerifyError(
                "attestation report exceeds 1 MiB envelope cap".into(),
            ));
        }
        // Parse the wire envelope.
        let wire: SnpWire = bincode::deserialize(&attestation.report)
            .map_err(|e| AttestationError::VerifyError(format!("deserialize envelope: {e:?}")))?;
        if wire.report_bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(AttestationError::VerifyError(
                "inner report exceeds 1 MiB cap".into(),
            ));
        }
        if let Some(certs) = &wire.cert_table {
            for (_, der) in certs {
                if der.len() > MAX_ENVELOPE_BYTES {
                    return Err(AttestationError::VerifyError(
                        "inner cert exceeds 1 MiB cap".into(),
                    ));
                }
            }
        }

        // Parse the SNP report body.
        let report = AttestationReport::from_bytes(&wire.report_bytes)
            .map_err(|e| AttestationError::VerifyError(format!("parse report: {e:?}")))?;

        // Bind check: the report's report_data field must equal the
        // caller-supplied user_data. This is technically redundant
        // with the `attestation.user_data` check above, but we repeat
        // it against the authentic report bytes so a forged envelope
        // cannot bypass it.
        if report.report_data != *expected_user_data {
            return Err(AttestationError::VerifyError(
                "report.report_data != expected_user_data".into(),
            ));
        }

        // Reconstruct the cert chain. When `cert_table` is present we
        // build (ARK, ASK, VCEK) from the host-cached DER bytes.
        // Otherwise we have no trust anchor — refuse.
        let cert_table = wire.cert_table.ok_or_else(|| {
            AttestationError::VerifyError("no cert table in attestation envelope".into())
        })?;
        let chain = chain_from_cert_table(&cert_table)?;

        // Chain self-check + report sig.
        chain
            .verify()
            .map_err(|e| AttestationError::VerifyError(format!("chain: {e:?}")))?;
        (&chain, &report)
            .verify()
            .map_err(|e| AttestationError::VerifyError(format!("report sig: {e:?}")))?;

        Ok(())
    }
}

/// Envelope we serialize with bincode when sending an attestation to a
/// peer. Holds the raw SNP report bytes and the host-cached cert
/// table exported by `get_ext_report`.
#[derive(serde::Serialize, serde::Deserialize)]
struct SnpWire {
    /// Raw SNP report bytes (0x4A0 layout per AMD SEV-SNP ABI).
    report_bytes: Vec<u8>,
    /// Optional cert table: each entry is (guid, der_bytes).
    cert_table: Option<Vec<(String, Vec<u8>)>>,
}

/// Serialize a `CertTableEntry` slice to a portable (guid, bytes)
/// vector. The virtee/sev `CertTableEntry` type is not directly
/// serde-serializable in 6.3.x without pulling in additional deps.
///
/// Uses format strings that include the UUID for `OTHER` variants
/// so multiple unknown-type certs cannot collide under the same
/// label and subsequently drop one in `chain_from_cert_table`.
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
                // No catch-all: if a future virtee/sev variant is
                // introduced the compiler will flag this match and
                // force an explicit decision.
                sev::firmware::host::CertType::Empty => "empty".to_string(),
            };
            (guid, e.data.clone())
        })
        .collect()
}

/// Build a `snp::Chain` from a cert table. Requires ARK, ASK, and
/// VCEK to be present.
fn chain_from_cert_table(
    table: &[(String, Vec<u8>)],
) -> Result<sev::certs::snp::Chain, AttestationError> {
    use sev::certs::snp::{ca, Certificate, Chain};

    let find = |name: &str| {
        table
            .iter()
            .find(|(g, _)| g == name)
            .map(|(_, der)| der.as_slice())
    };

    let ark_der = find("ark").ok_or_else(|| {
        AttestationError::VerifyError("cert table missing ARK".into())
    })?;
    let ask_der = find("ask").ok_or_else(|| {
        AttestationError::VerifyError("cert table missing ASK".into())
    })?;
    let vcek_der = find("vcek").ok_or_else(|| {
        AttestationError::VerifyError("cert table missing VCEK".into())
    })?;

    let ark = Certificate::from_der(ark_der)
        .map_err(|e| AttestationError::VerifyError(format!("parse ARK: {e:?}")))?;
    let ask = Certificate::from_der(ask_der)
        .map_err(|e| AttestationError::VerifyError(format!("parse ASK: {e:?}")))?;
    let vcek = Certificate::from_der(vcek_der)
        .map_err(|e| AttestationError::VerifyError(format!("parse VCEK: {e:?}")))?;

    let ca = ca::Chain { ark, ask };
    Ok(Chain { ca, vcek })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sev_snp_provider_fails_without_device() {
        // In a test environment (even on Linux) there is no
        // /dev/sev-guest. Provider construction must fail cleanly.
        if !is_sev_snp_guest() {
            assert!(SevSnpProvider::new().is_err());
        }
    }
}
