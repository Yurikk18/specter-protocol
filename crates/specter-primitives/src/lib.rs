pub mod pedersen;
pub mod scalar_utils;
pub mod shamir;
pub mod sis;

/// Hardware side-channel hardening (scalar blinding, projective
/// randomization, dummy operations). Gated behind the `hardened`
/// feature flag so callers opt in.
#[cfg(feature = "hardened")]
pub mod hardened;

/// 64-bit bit-decomposition range proof primitive for confidential
/// transactions. Gated behind the `confidential-tx` feature so
/// current deployments that keep `value: u64` plaintext pay zero
/// cost.
#[cfg(feature = "confidential-tx")]
pub mod range_proof;
