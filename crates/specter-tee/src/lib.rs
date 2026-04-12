//! Confidential-VM attestation and key sealing for Specter Protocol.
//!
//! Intended to replace the (sunset) Intel SGX path with AMD SEV-SNP,
//! which isolates the entire guest VM rather than per-process enclaves
//! and is available on Azure, AWS, and GCP as of 2024.
//!
//! # What this crate provides
//!
//! 1. [`Attestation`]: an opaque type that holds a SEV-SNP attestation
//!    report signed by the AMD Platform Security Processor (PSP). The
//!    report can be sent to a remote peer who verifies that the sender
//!    is running inside a legitimate SEV-SNP VM with a specific
//!    measurement.
//!
//! 2. [`AttestationProvider`] trait and a SEV-SNP backend that wraps
//!    the [`sev`](https://crates.io/crates/sev) crate to request
//!    reports with caller-supplied `user_data` (e.g., the hash of a
//!    mint public key).
//!
//! 3. Automatic fallback to `specter-core::memory_guard` when no TEE
//!    is available — the rest of the protocol keeps functioning with
//!    best-effort software protection.
//!
//! # Threat model
//!
//! SEV-SNP protects against:
//! - Malicious hypervisor reading guest memory (AES-256 memory encryption)
//! - Rogue kernel or OS on the host
//! - DMA attacks from other guests
//!
//! SEV-SNP does NOT protect against:
//! - Physical probing of the CPU die
//! - Side-channel attacks on the PSP itself
//! - Compromise of the AMD root key (root-of-trust compromise)
//! - **Replay of a captured attestation** — there is no timestamp
//!   or freshness binding in the raw report format beyond the
//!   `user_data` field. Applications that need freshness must mix a
//!   verifier-issued nonce into `user_data` via
//!   [`user_data_from_pubkey_and_nonce`].
//!
//! # Detection
//!
//! At runtime `detect_platform()` returns the strongest available TEE.
//! Production deployments should `assert_eq!(detect_platform(),
//! Platform::SevSnp)` to fail loudly if a binary built with the
//! `sev-snp` feature is launched outside a confidential VM.

use thiserror::Error;

pub mod tcb_policy;
pub use tcb_policy::{TcbPolicy, TcbPolicyViolation};

/// Platform-independent SEV-SNP attestation **verification**. Works
/// on Windows, macOS, and Linux via the pure-Rust `crypto_nossl`
/// backend. Only the `sev-snp` feature is required — no Linux kernel.
#[cfg(feature = "sev-snp")]
pub mod sev_snp_verify;

/// Linux-only SEV-SNP attestation **request** backend. Needs
/// `/dev/sev-guest` exposed by kernel 5.19+.
#[cfg(all(target_os = "linux", feature = "sev-snp"))]
pub mod sev_snp;

/// Available confidential-compute platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// No TEE detected. Fall back to memory_guard (mlock + zeroize).
    None,
    /// AMD SEV-SNP confidential VM with /dev/sev-guest present.
    SevSnp,
}

/// Detect which confidential-compute platform is available at runtime.
///
/// This is a pure detection — it does NOT request an attestation.
/// Callers should call this at startup and propagate the result into
/// the signer selection logic: if `Platform::SevSnp` is available,
/// prefer the SEV-SNP-backed signer; otherwise fall back to
/// `SoftwareSigner` with `memory_guard`-hardened allocations.
pub fn detect_platform() -> Platform {
    #[cfg(all(target_os = "linux", feature = "sev-snp"))]
    {
        if sev_snp::is_sev_snp_guest() {
            return Platform::SevSnp;
        }
    }
    Platform::None
}

/// An attestation report produced by a confidential-compute platform.
///
/// Contains:
/// - the raw report bytes (signed by the PSP / hardware root of trust)
/// - the platform that produced it
/// - the user_data field that was bound into the report
#[derive(Clone, Debug)]
pub struct Attestation {
    pub platform: Platform,
    pub report: Vec<u8>,
    pub user_data: [u8; 64],
}

/// Errors produced by the attestation subsystem.
#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("no confidential-compute platform available")]
    PlatformUnavailable,

    #[error("SEV-SNP guest device /dev/sev-guest not accessible: {0}")]
    SnpDeviceError(String),

    #[error("SEV-SNP report request failed: {0}")]
    SnpReportError(String),

    #[error("attestation verification failed: {0}")]
    VerifyError(String),

    #[error("TCB policy violation: {0}")]
    TcbPolicyViolation(#[from] TcbPolicyViolation),
}

/// A backend that produces and verifies attestation reports.
pub trait AttestationProvider {
    /// Request a fresh attestation report with 64 bytes of user_data
    /// bound into it. The user_data is typically the hash of a public
    /// key the caller wants to prove they generated inside the
    /// confidential VM.
    fn request_report(&self, user_data: &[u8; 64]) -> Result<Attestation, AttestationError>;

    /// Verify a peer's attestation report. Returns `Ok(())` if the
    /// report was signed by the expected hardware root of trust AND
    /// binds the expected user_data AND passes the TCB policy checks
    /// (minimum firmware version, allowed measurements, max VMPL).
    fn verify_report(
        &self,
        attestation: &Attestation,
        expected_user_data: &[u8; 64],
        policy: &TcbPolicy,
    ) -> Result<(), AttestationError>;
}

/// A no-op attestation provider used when no TEE is available. Every
/// `request_report` call returns an error so callers cannot
/// accidentally ship a "fake attestation" in production.
pub struct NullAttestationProvider;

impl AttestationProvider for NullAttestationProvider {
    fn request_report(&self, _user_data: &[u8; 64]) -> Result<Attestation, AttestationError> {
        Err(AttestationError::PlatformUnavailable)
    }

    fn verify_report(
        &self,
        _attestation: &Attestation,
        _expected_user_data: &[u8; 64],
        _policy: &TcbPolicy,
    ) -> Result<(), AttestationError> {
        Err(AttestationError::PlatformUnavailable)
    }
}

/// Hash a Ristretto public key to 64 bytes suitable for SEV-SNP
/// `user_data` binding. Uses SHA-512 with a domain tag so the binding
/// cannot collide with any other specter hash-to-bytes usage.
///
/// **Replay note**: this function does NOT include a freshness
/// nonce, so a captured attestation can be replayed for the same
/// key. Applications that need freshness must use
/// [`user_data_from_pubkey_and_nonce`] and have the verifier issue
/// a fresh challenge per attestation.
pub fn user_data_from_pubkey(pk_compressed: &[u8; 32]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let hash = Sha512::new()
        .chain_update(b"specter-tee-user-data:")
        .chain_update(pk_compressed)
        .finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&hash);
    out
}

/// Hash a Ristretto public key + a verifier-issued nonce to 64 bytes
/// suitable for SEV-SNP `user_data` binding.
///
/// Prevents replay of captured attestations. The verifier is
/// responsible for generating `nonce` freshly per request and for
/// remembering which nonces it has accepted to avoid race-condition
/// replays.
pub fn user_data_from_pubkey_and_nonce(
    pk_compressed: &[u8; 32],
    nonce: &[u8],
) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let hash = Sha512::new()
        .chain_update(b"specter-tee-user-data-nonce:")
        .chain_update(pk_compressed)
        .chain_update((nonce.len() as u64).to_be_bytes())
        .chain_update(nonce)
        .finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&hash);
    out
}

/// A verifier-only provider that can verify SEV-SNP attestation
/// reports on **any platform** but cannot request new reports (no
/// `/dev/sev-guest`). Use this in validator nodes running outside a
/// confidential VM, or on Windows / macOS CI.
#[cfg(feature = "sev-snp")]
pub struct PortableSnpVerifier;

#[cfg(feature = "sev-snp")]
impl AttestationProvider for PortableSnpVerifier {
    fn request_report(&self, _: &[u8; 64]) -> Result<Attestation, AttestationError> {
        Err(AttestationError::PlatformUnavailable)
    }

    fn verify_report(
        &self,
        attestation: &Attestation,
        expected_user_data: &[u8; 64],
        policy: &TcbPolicy,
    ) -> Result<(), AttestationError> {
        sev_snp_verify::verify_snp_report(attestation, expected_user_data, policy)
    }
}

#[cfg(feature = "sev-snp")]
pub use sev_snp_verify::verify_snp_report;

#[cfg(feature = "mock-attestation")]
pub mod mock;

#[cfg(feature = "mock-attestation")]
pub use mock::MockAttestationProvider;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_provider_rejects_requests() {
        let p = NullAttestationProvider;
        let user_data = [0u8; 64];
        assert!(p.request_report(&user_data).is_err());
    }

    #[test]
    fn test_platform_detection_does_not_panic() {
        // The detection path must be safe on any target — it is the
        // startup gate for the whole crate.
        let _ = detect_platform();
    }

    #[test]
    fn test_user_data_deterministic() {
        let pk = [42u8; 32];
        let u1 = user_data_from_pubkey(&pk);
        let u2 = user_data_from_pubkey(&pk);
        assert_eq!(u1, u2);
    }

    #[test]
    fn test_user_data_sensitive_to_input() {
        let u1 = user_data_from_pubkey(&[1u8; 32]);
        let u2 = user_data_from_pubkey(&[2u8; 32]);
        assert_ne!(u1, u2);
    }

    #[test]
    fn test_user_data_with_nonce_differs_from_plain() {
        let pk = [7u8; 32];
        let u1 = user_data_from_pubkey(&pk);
        let u2 = user_data_from_pubkey_and_nonce(&pk, b"nonce-1");
        assert_ne!(u1, u2);
    }

    #[test]
    fn test_user_data_with_distinct_nonces_differ() {
        let pk = [7u8; 32];
        let u1 = user_data_from_pubkey_and_nonce(&pk, b"nonce-1");
        let u2 = user_data_from_pubkey_and_nonce(&pk, b"nonce-2");
        assert_ne!(u1, u2);
    }

    #[test]
    fn test_default_platform_is_none_without_sev_feature() {
        // In the default (non-feature) build there is no way to get
        // SevSnp back from detect_platform.
        #[cfg(not(feature = "sev-snp"))]
        assert_eq!(detect_platform(), Platform::None);
    }
}
