//! Platform-independent SEV-SNP attestation verification.
//!
//! This module contains only pure-crypto verification logic (ECDSA-P384
//! chain validation + report signature check) and works on **any**
//! platform — Windows, macOS, Linux — because it depends only on the
//! pure-Rust `crypto_nossl` backend of the virtee/sev crate.
//!
//! Requesting attestation reports (the ioctl to `/dev/sev-guest`) is
//! Linux-only and lives in `sev_snp.rs` behind a `target_os = "linux"`
//! gate.
//!
//! The verification enforces:
//! 1. User-data binding (report.report_data == expected).
//! 2. Certificate chain (ARK self-sig → ARK→ASK → ASK→VCEK).
//! 3. Report signature (VCEK signs the report body).
//! 4. TCB policy (firmware floor, measurement allow-list, max VMPL).
//! 5. Envelope size cap (1 MiB against DoS).

#![cfg(feature = "sev-snp")]

use crate::{Attestation, AttestationError, Platform, TcbPolicy};

/// Maximum envelope size (1 MiB) to prevent unbounded allocation.
const MAX_ENVELOPE_BYTES: usize = 1 << 20;

/// Verify an SEV-SNP attestation report against its certificate chain
/// and a TCB policy. Works on any platform.
pub fn verify_snp_report(
    attestation: &Attestation,
    expected_user_data: &[u8; 64],
    policy: &TcbPolicy,
) -> Result<(), AttestationError> {
    use sev::certs::snp::Verifiable;
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
    // Envelope size cap.
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

    // Bind check against the authentic report bytes.
    // sev 6.3.1 uses Array<u8, 64>, not [u8; 64].
    if report.report_data.as_ref() != expected_user_data {
        return Err(AttestationError::VerifyError(
            "report.report_data != expected_user_data".into(),
        ));
    }

    // Reconstruct the cert chain.
    let cert_table = wire.cert_table.ok_or_else(|| {
        AttestationError::VerifyError("no cert table in attestation envelope".into())
    })?;
    let chain = chain_from_cert_table(&cert_table)?;

    // Chain self-check + report signature.
    chain
        .verify()
        .map_err(|e| AttestationError::VerifyError(format!("chain: {e:?}")))?;
    (&chain, &report)
        .verify()
        .map_err(|e| AttestationError::VerifyError(format!("report sig: {e:?}")))?;

    // TCB policy enforcement.
    // sev 6.3.1 TcbVersion has named component fields.
    let tcb = &report.current_tcb;
    let measurement: [u8; 48] = {
        let mut m = [0u8; 48];
        m.copy_from_slice(report.measurement.as_ref());
        m
    };
    policy
        .check(
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode,
            &measurement,
            report.vmpl,
        )
        .map_err(AttestationError::TcbPolicyViolation)?;

    Ok(())
}

/// Envelope struct serialized with bincode. Shared between the
/// Linux request side and the portable verify side.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct SnpWire {
    pub report_bytes: Vec<u8>,
    pub cert_table: Option<Vec<(String, Vec<u8>)>>,
}

/// Build a `snp::Chain` from a cert table.
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
    Ok(Chain { ca, vek: vcek })
}
