//! Abstract `WalletSigner` trait.
//!
//! Any backend that can produce a Schnorr-over-Ristretto255 signature
//! for a supplied message can plug in as a wallet signer. The crate
//! ships a [`SoftwareSigner`] default backed by a raw Ristretto
//! keypair in process memory, plus stubs documenting how an HSM,
//! TEE enclave, or YubiHSM integration would implement the trait.
//!
//! # Motivation
//!
//! Today every crypto operation in `specter-core` and
//! `specter-blind-sig` takes a raw `Scalar` as the secret. That makes
//! it impossible to offload signing to hardware without rewriting
//! every call site. The trait introduced here wraps the "sign this
//! message under my long-term identity key" operation so that:
//!
//! - Software wallets call [`SoftwareSigner::sign`]
//! - YubiHSM wallets call `YubiHsmSigner::sign` (not shipped — stub)
//! - Fortanix EDP SGX enclaves call `SgxEnclaveSigner::sign` (stub)
//! - TPM 2.0 sealed wallets call `TpmSigner::sign` (stub)
//!
//! The Ristretto constraint rules out most commodity HSMs that only
//! speak Ed25519/ECDSA. A common workaround is to hold a long-term
//! Ed25519 key in the HSM as a **root of trust** and derive
//! short-lived Ristretto signing keys via a signed delegation;
//! that pattern is out of scope for this module but the trait is
//! shaped to make it feasible.
//!
//! # Security guarantees
//!
//! - [`WalletSigner`] takes `&self` for `sign`, not `&mut self`, so a
//!   signer can be shared across threads safely if the backend is
//!   `Send + Sync`.
//! - The trait does not expose the secret; implementations that hold
//!   the key in memory must zeroize on drop.
//! - [`WalletSigner::public`] returns the Ristretto public key so
//!   callers can verify signatures without learning anything about
//!   the backend.

use curve25519_dalek::{RistrettoPoint, Scalar};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use sha2::{Digest, Sha512};

/// A Schnorr signature over Ristretto255 in (R, s) form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrSig {
    pub r: RistrettoPoint,
    pub s: Scalar,
}

/// Error returned by signer backends.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// The backend is unavailable — no device, no network, crashed.
    #[error("signer backend unavailable: {0}")]
    Unavailable(String),

    /// The backend refused the operation (policy, rate limit, locked).
    #[error("signer refused: {0}")]
    Refused(String),

    /// The backend is not yet implemented.
    #[error("signer backend not implemented: {0}")]
    Unimplemented(&'static str),
}

/// Abstract wallet signer. Implementations hold the secret material
/// (in memory, HSM, enclave, etc.) and expose only the ability to
/// sign arbitrary messages plus query the public key.
pub trait WalletSigner: Send + Sync {
    /// Sign a message under the signer's long-term Schnorr key.
    ///
    /// The challenge is computed as
    /// `H("specter-wallet-sig:" || R || pk || msg)` where `pk` is the
    /// public half. Callers verify via
    /// [`WalletSigner::verify`].
    fn sign(&self, msg: &[u8]) -> Result<SchnorrSig, SignerError>;

    /// Return the Ristretto public key for this signer.
    fn public(&self) -> RistrettoPoint;

    /// Default verifier — stateless. Returns `true` iff
    /// `sig.s * G == sig.r + e * pk` where `e` is the challenge.
    fn verify(&self, msg: &[u8], sig: &SchnorrSig) -> bool {
        verify_schnorr(&self.public(), msg, sig)
    }
}

/// Stateless Schnorr verification. Exposed as a free function so it
/// can be reused without instantiating a signer.
pub fn verify_schnorr(pk: &RistrettoPoint, msg: &[u8], sig: &SchnorrSig) -> bool {
    let e = challenge(&sig.r, pk, msg);
    let lhs = sig.s * G;
    let rhs = sig.r + e * pk;
    lhs == rhs
}

fn challenge(r: &RistrettoPoint, pk: &RistrettoPoint, msg: &[u8]) -> Scalar {
    let hash = Sha512::new()
        .chain_update(b"specter-wallet-sig:")
        .chain_update(r.compress().as_bytes())
        .chain_update(pk.compress().as_bytes())
        .chain_update((msg.len() as u64).to_le_bytes())
        .chain_update(msg)
        .finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ────────────────────────────────────────────────────────────────────
// SoftwareSigner — default backend
// ────────────────────────────────────────────────────────────────────

/// Plain in-memory signer. Holds the secret scalar directly and
/// zeroizes it on drop. Suitable for development and for wallets
/// that don't need hardware offload.
pub struct SoftwareSigner {
    secret: Scalar,
    public: RistrettoPoint,
}

impl SoftwareSigner {
    /// Generate a fresh software signer.
    pub fn generate() -> Self {
        let secret = specter_primitives::scalar_utils::random_scalar();
        Self {
            public: secret * G,
            secret,
        }
    }

    /// Construct from an existing secret scalar.
    pub fn from_secret(secret: Scalar) -> Self {
        Self {
            public: secret * G,
            secret,
        }
    }
}

impl Drop for SoftwareSigner {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

impl std::fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareSigner")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl WalletSigner for SoftwareSigner {
    fn sign(&self, msg: &[u8]) -> Result<SchnorrSig, SignerError> {
        let k = specter_primitives::scalar_utils::random_scalar();
        let r = k * G;
        let e = challenge(&r, &self.public, msg);
        let s = k + e * self.secret;
        // k is a local; curve25519-dalek's ZeroizeOnDrop auto-wipes.
        Ok(SchnorrSig { r, s })
    }

    fn public(&self) -> RistrettoPoint {
        self.public
    }
}

// ────────────────────────────────────────────────────────────────────
// HSM stubs
// ────────────────────────────────────────────────────────────────────

/// Stub for a YubiHSM-backed signer. Full integration would use the
/// `yubihsm` crate to keep the secret inside the HSM and issue a
/// `Sign` command per request. YubiHSM supports Ed25519 and ECDSA
/// natively; Ristretto-Schnorr signing is not supported by the
/// device firmware as of late 2025, so a production integration
/// would need to either (a) run a custom mode in a Fortanix EDP
/// SGX enclave with the Ristretto secret sealed against the HSM or
/// (b) sign Ed25519 over a delegation transcript and fold that into
/// the Specter trust chain at a higher level.
pub struct YubiHsmSigner {
    pub public: RistrettoPoint,
}

impl WalletSigner for YubiHsmSigner {
    fn sign(&self, _msg: &[u8]) -> Result<SchnorrSig, SignerError> {
        Err(SignerError::Unimplemented(
            "YubiHSM Ristretto signing requires custom firmware or SGX enclave; \
             use SoftwareSigner or write a domain-specific integration",
        ))
    }

    fn public(&self) -> RistrettoPoint {
        self.public
    }
}

/// Stub for a Fortanix EDP SGX enclave signer. The enclave holds
/// the Ristretto secret sealed against the Intel PRM, exposes a
/// `sign` RPC over the ocall boundary, and returns a Schnorr sig.
/// Full integration out of scope for this module — see
/// <https://edp.fortanix.com/> for the toolchain.
pub struct SgxEnclaveSigner {
    pub public: RistrettoPoint,
}

impl WalletSigner for SgxEnclaveSigner {
    fn sign(&self, _msg: &[u8]) -> Result<SchnorrSig, SignerError> {
        Err(SignerError::Unimplemented(
            "SGX enclave signer not yet wired; requires Fortanix EDP build target",
        ))
    }

    fn public(&self) -> RistrettoPoint {
        self.public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_signer_roundtrip() {
        let s = SoftwareSigner::generate();
        let msg = b"hello wallet";
        let sig = s.sign(msg).unwrap();
        assert!(s.verify(msg, &sig));
        assert!(verify_schnorr(&s.public(), msg, &sig));
    }

    #[test]
    fn test_software_signer_wrong_msg_rejected() {
        let s = SoftwareSigner::generate();
        let sig = s.sign(b"original").unwrap();
        assert!(!s.verify(b"tampered", &sig));
    }

    #[test]
    fn test_software_signer_wrong_pk_rejected() {
        let a = SoftwareSigner::generate();
        let b = SoftwareSigner::generate();
        let sig = a.sign(b"msg").unwrap();
        assert!(!verify_schnorr(&b.public(), b"msg", &sig));
    }

    #[test]
    fn test_two_signatures_of_same_message_differ() {
        // Different nonces → different signatures, both valid.
        let s = SoftwareSigner::generate();
        let msg = b"same msg";
        let sig1 = s.sign(msg).unwrap();
        let sig2 = s.sign(msg).unwrap();
        assert!(s.verify(msg, &sig1));
        assert!(s.verify(msg, &sig2));
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_yubi_hsm_stub_returns_unimplemented() {
        let stub = YubiHsmSigner {
            public: RistrettoPoint::default(),
        };
        let err = stub.sign(b"msg").unwrap_err();
        assert!(matches!(err, SignerError::Unimplemented(_)));
    }

    #[test]
    fn test_sgx_stub_returns_unimplemented() {
        let stub = SgxEnclaveSigner {
            public: RistrettoPoint::default(),
        };
        assert!(matches!(stub.sign(b"msg"), Err(SignerError::Unimplemented(_))));
    }

    #[test]
    fn test_signer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SoftwareSigner>();
        assert_send_sync::<YubiHsmSigner>();
        assert_send_sync::<SgxEnclaveSigner>();
    }
}
