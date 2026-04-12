//! # Symmetric Blind Tokens (SBT)
//!
//! A post-quantum-READY replacement for the classical Schnorr blind
//! signature at the heart of Specter's mint flow. Ships today with
//! **classical security** via a carefully composed threshold DH-OPRF
//! plus Schnorr/Chaum-Pedersen NIZK. The external trait surface is
//! stable so the internals can swap to VOLE-in-the-head + lattice OPRF
//! when generic VOLEitH Rust crates mature.
//!
//! # Construction (informal)
//!
//! 1. The client picks a random secret `s`. It forms a Pedersen
//!    commitment `C = g^s · h^r` where `(g, h)` are NUMS generators
//!    from [`specter_primitives::pedersen`].
//! 2. The client hashes `C` into a Ristretto point `P = H2C(C)` and
//!    sends `B = P · α` to the mint, where `α` is a fresh random
//!    scalar (the **blinding factor**).
//! 3. The mint holds a threshold-shared OPRF key `k` (Feldman-VSS
//!    shared across `n` trustees). A quorum of `t` trustees each
//!    compute `B_i = B · k_i` and a Chaum-Pedersen NIZK proving
//!    `B_i = B · k_i ∧ Y_i = G · k_i` for a published share
//!    commitment `Y_i = G · k_i`. See [`oprf::ServerEvaluation`] and
//!    [`proof::DdhEqualityProof`].
//! 4. The client combines the verified shares with Lagrange
//!    interpolation in the exponent to obtain `B_k = B · k`. It
//!    unblinds by multiplying by `α⁻¹`, yielding `T = P · k = F_k(C)`.
//! 5. The client outputs a **spend token** `(C, σ_T)` where `σ_T` is
//!    a Schnorr-style NIZK proving knowledge of `s, r` such that
//!    `C = g^s · h^r` AND possession of the OPRF output tag `T`. The
//!    **nullifier** the protocol records is `nullifier = H_null(T)`.
//!
//! # Why this matters
//!
//! - **Unlinkability.** From the mint's view every signing interaction
//!   sees only the uniformly random blinded point `B`, independent of
//!   `C`. Unblinding in the exponent is standard OPRF unlinkability.
//! - **One-more-unforgeability.** Reduces to one-more Gap-CDH on
//!   Ristretto255 in the ROM (Jarecki-Krawczyk-Xu 2014 / Hauck-Kiltz
//!   2019 framing). Identical in structure to the classical
//!   `2HashDH` OPRF.
//! - **Threshold.** Losing up to `t-1` trustees reveals no information
//!   about `k`; the NIZK of DDH equality prevents a malicious trustee
//!   from poisoning the combined output without detection.
//! - **Double-spend prevention.** `T` is deterministic in `C` and
//!   unique across the lifetime of key `k`, so `H_null(T)` serves as
//!   a collision-resistant nullifier. The nullifier set semantics
//!   match the existing PCT scheme — see `specter-core::nullifier`.
//! - **PQ upgrade path.** The [`BlindSignatureScheme`] trait abstracts
//!   away the specific primitive. Swapping the DH-OPRF core for a
//!   lattice-based OPRF (e.g., Leap — Eurocrypt 2025) and the Schnorr
//!   NIZK for a VOLEitH R1CS (via a future generic QuickSilver Rust
//!   crate) is a drop-in replacement that preserves the protocol-
//!   level invariants above.
//!
//! # Key loss
//!
//! If a client loses its `client_secret`, all SBTs previously minted
//! under that secret become unrecoverable: the commitments and
//! nullifiers they produced remain on-chain, but regenerating with
//! a fresh secret mints *new* tokens with distinct nullifiers. By
//! design there is no migration path — hiding `(s, r)` behind
//! `client_secret` is precisely what stops a mint from linking user
//! flows, and the same mechanism prevents key recovery. Production
//! deployments must back up `client_secret` out-of-band via the
//! wallet encryption layer in `specter-core` before the user mints
//! any tokens.
//!
//! # Namespace separation
//!
//! SBT nullifiers are returned as [`scheme::SbtNullifier`], a
//! newtype wrapper that is intentionally *not* convertible `as [u8;
//! 32]` without an explicit `.into_bytes()` call. This prevents an
//! accidental feed of an SBT nullifier into
//! `specter-core::nullifier::compute_nullifier`'s output space,
//! which uses a different SHAKE domain tag
//! (`"specter-nullifier:"`). Both spaces are cryptographically
//! disjoint, but the type-level barrier is additional defense in
//! depth.
//!
//! # What this crate does NOT provide
//!
//! - **Setup of the OPRF key.** Key generation uses the existing
//!   Feldman-VSS DKG in `specter-blind-sig::dkg`. This crate only
//!   consumes share commitments (`Y_i = G·k_i`) and the per-trustee
//!   scalar shares.
//! - **Transport.** The `ServerEvaluation` and `ClientRequest` types
//!   are `Serialize` and intended to be sent via the existing
//!   `specter-net` framed protocol.
//! - **Nullifier storage.** The `SpendToken::nullifier()` method
//!   returns a 32-byte digest. Persistence and anti-replay happen in
//!   `specter-core::nullifier`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod oprf;
pub mod proof;
pub mod scheme;
pub mod transcript;

pub use oprf::{
    blind, combine_evaluations, unblind, OprfBlinding, OprfEvaluation, OprfPublicKey,
    OprfSecretShare, OprfServerCommit,
};
pub use proof::{DdhEqualityProof, TokenProof};
pub use scheme::{BlindSignatureScheme, SbtNullifier, SbtScheme, SpendToken};

use thiserror::Error;

/// Errors produced by the Symmetric Blind Token subsystem.
#[derive(Debug, Error)]
pub enum SbtError {
    /// A Chaum-Pedersen DDH-equality NIZK failed to verify. Indicates
    /// a malicious trustee returned `B_i ≠ B·k_i`.
    #[error("DDH equality proof verification failed for trustee {0}")]
    DdhEqualityFailed(u32),

    /// Not enough valid server evaluations to reach threshold.
    #[error("insufficient valid evaluations: got {got}, need {need}")]
    Insufficient {
        /// How many valid evaluations were supplied.
        got: usize,
        /// Threshold required.
        need: usize,
    },

    /// Duplicate trustee index in a combine set.
    #[error("duplicate trustee index {0} in evaluation set")]
    DuplicateIndex(u32),

    /// Token NIZK proof of knowledge failed to verify.
    #[error("spend token NIZK verification failed")]
    TokenProofFailed,

    /// A point deserialized to the identity (rejected to avoid
    /// small-subgroup / zero-order edge cases).
    #[error("decoded point is the identity — rejecting")]
    IdentityPoint,

    /// Lagrange interpolation received a zero denominator.
    #[error("lagrange denominator is zero — degenerate evaluation set")]
    ZeroDenominator,

    /// A party submitted a trustee index of 0 (Shamir's secret
    /// coordinate) or an invalid shamir index.
    #[error("invalid trustee index {0}")]
    InvalidIndex(u32),

    /// Session id shorter than [`crate::scheme::MIN_SESSION_ID_LEN`].
    #[error("session id is too short")]
    SessionTooShort,

    /// Request's session id does not match the scheme's canonical
    /// session id.
    #[error("session id mismatch between request and scheme")]
    SessionMismatch,

    /// `finalize` was called with a request that does not correspond
    /// to the provided client state.
    #[error("client state and request are inconsistent")]
    StateRequestMismatch,

    /// H2C domain tag is empty (would allow cross-protocol
    /// collisions).
    #[error("h2c_domain must not be empty")]
    EmptyDomain,

    /// Tag-origin check failed: `tag ≠ H2C(commitment) · k` for the
    /// supplied secret key.
    #[error("tag is not bound to the claimed OPRF key")]
    TagOriginMismatch,

    /// Two quorums disagree on the aggregate OPRF public key, or
    /// the caller-provided `expected_public_key` does not match the
    /// computed one.
    #[error("aggregate public key mismatch — commits are inconsistent")]
    AggregateMismatch,

    /// `verify_token` cannot perform full validation because the
    /// scheme has no held secret key. Production deployments must
    /// compose `verify_token` with a threshold re-combine check.
    #[error("full tag-origin validation requires a held secret key or threshold helper")]
    TagOriginCheckRequired,
}
