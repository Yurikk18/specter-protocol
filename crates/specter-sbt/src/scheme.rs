//! High-level `BlindSignatureScheme` trait and the `SbtScheme`
//! implementation that composes the OPRF + NIZK into a working
//! blind-token mint/spend flow.
//!
//! # Verification model
//!
//! Classical DH-OPRF (which this crate implements in v0.1) does **not**
//! give a publicly-verifiable tag without a pairing or a lattice-based
//! relation. The `verify_token` method performs only **client-side
//! proof validation**:
//!
//! - Pedersen commitment opening PoK (Schnorr NIZK) — binds the
//!   token to a specific `(s, r)` that the client knows.
//! - Aggregate OPRF public key `Y` is bound into the transcript so a
//!   token minted under one mint key cannot be replayed against a
//!   verifier expecting a different key.
//! - Structural invariants (identity-point rejection, session length,
//!   session consistency).
//!
//! For **tag-origin** validation — "`T = H2C(C)·k` for the real mint
//! key `k`" — production deployments MUST invoke one of:
//!
//! - `SbtScheme::verify_tag_with_secret_key(token, &k)` — if the
//!   verifier holds `k` directly (single-trustee case, or a
//!   centralized mint rerunning the check).
//! - A second threshold OPRF round at spend time: each validator
//!   computes `T_i' = H2C(C)·k_i` with a fresh DDH-equality proof,
//!   the responses are Lagrange-combined, and `T'` is compared to
//!   `token.tag`. This can reuse `evaluate_server` and
//!   `combine_evaluations` over the unblinded `H2C(C)`.
//!
//! Skipping tag-origin validation gives an attacker with any scalar
//! `k'` the ability to mint a self-consistent "token" that passes
//! `verify_token`; the nullifier it produces will not collide with
//! legitimate tokens (high-entropy under ROM), but a naive verifier
//! that trusts `verify_token` alone would grant spendable value. The
//! trait's `verify_token` is therefore labelled a **soundness ceiling**
//! in its documentation — callers must compose it with one of the
//! tag-origin checks above.

use crate::oprf::{
    blind, combine_evaluations, hash_to_curve, unblind, OprfBlinding, OprfEvaluation,
    OprfPublicKey, OprfSecretShare, OprfServerCommit,
};
use crate::proof::TokenProof;
use crate::SbtError;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use specter_primitives::pedersen::PedersenParams;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Minimum session id length enforced by the scheme. 16 bytes of
/// randomness is enough to make session collisions negligible across
/// a trillion mint interactions.
pub const MIN_SESSION_ID_LEN: usize = 16;

/// A 32-byte nullifier scoped to the SBT scheme.
///
/// Newtype wrapper so SBT nullifiers cannot be accidentally mixed
/// with the 32-byte nullifiers produced by
/// `specter-core::nullifier::compute_nullifier`. Both live in
/// disjoint cryptographic namespaces (distinct SHAKE domain tags),
/// but the type system would not otherwise catch a refactor that
/// crossed them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SbtNullifier(pub [u8; 32]);

impl SbtNullifier {
    /// Raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Into raw 32 bytes. Use this deliberate conversion when
    /// crossing into the generic `specter-core::nullifier::NullifierSet`.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A minimal, primitive-agnostic blind signature scheme trait.
///
/// The Specter mint flow was originally backed by threshold Schnorr
/// blind signatures (`specter-blind-sig`). This trait abstracts that
/// surface so the flow can swap to SBT (or, eventually, a VOLEitH +
/// lattice-OPRF construction) without touching call sites in
/// `specter-core`.
pub trait BlindSignatureScheme {
    /// Client-side secret state carried between `prepare` and
    /// `finalize`. Must be zeroized on drop.
    type ClientState: Zeroize;
    /// What the client sends to the signer (or signers).
    type ClientRequest: Serialize;
    /// What the signer (or each threshold share) returns.
    type ServerResponse: Serialize;
    /// The final unblinded token the client can later spend.
    type Token: Serialize;

    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Client: prepare a blinded request from a secret payload.
    fn prepare<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        payload: &[u8],
    ) -> Result<(Self::ClientState, Self::ClientRequest), Self::Error>;

    /// Client: combine the server responses and unblind the token.
    fn finalize<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        state: Self::ClientState,
        request: &Self::ClientRequest,
        responses: &[Self::ServerResponse],
    ) -> Result<Self::Token, Self::Error>;

    /// Verify the client-side proof of a token. See module-level
    /// documentation — this is a **soundness ceiling** that must be
    /// composed with a tag-origin check for full validity.
    fn verify_token(&self, token: &Self::Token) -> Result<(), Self::Error>;
}

/// Internal state for `SbtScheme`. All fields are private; the only
/// write path is [`SbtScheme::new`].
#[derive(Clone, Debug)]
struct SbtSchemeInner {
    pedersen: PedersenParams,
    commits: Vec<OprfServerCommit>,
    threshold: usize,
    h2c_domain: Vec<u8>,
    session_id: Vec<u8>,
    public_key: OprfPublicKey,
    /// Client master secret. Zeroized on drop.
    client_secret: [u8; 32],
    /// Optional held secret OPRF key for "full" verification. Only
    /// populated in test / single-party-mint deployments; production
    /// threshold deployments leave this `None` and rely on a
    /// threshold re-combine at spend time.
    secret_key: Option<Scalar>,
}

impl Drop for SbtSchemeInner {
    fn drop(&mut self) {
        self.client_secret.zeroize();
        if let Some(k) = self.secret_key.as_mut() {
            k.zeroize();
        }
    }
}

/// A concrete SBT scheme instance. Holds the public OPRF parameters
/// (threshold `t`, per-trustee commitments) plus the Pedersen
/// parameters used for the client-side commitment.
///
/// **Construction**: build via [`SbtScheme::new`], which validates
/// every field and rejects degenerate configurations. All internal
/// fields are private; there is no way to mutate a scheme after
/// construction, which makes all invariants hold for the lifetime
/// of the struct.
///
/// **Verification model**: see the module-level docs. A scheme
/// constructed without `secret_key` can only do *client-side proof*
/// validation; a scheme constructed with `secret_key` can do full
/// tag-origin validation.
#[derive(Clone, Debug)]
pub struct SbtScheme {
    inner: SbtSchemeInner,
}

/// Read-only accessors for SbtScheme public parameters. Kept narrow
/// on purpose — the only way to *mutate* the scheme is through
/// `SbtScheme::new`.
impl SbtScheme {
    /// Per-trustee public commitments, already validated.
    pub fn commits(&self) -> &[OprfServerCommit] {
        &self.inner.commits
    }

    /// Reconstruction threshold.
    pub fn threshold(&self) -> usize {
        self.inner.threshold
    }

    /// The session id this scheme instance binds into every proof.
    pub fn session_id(&self) -> &[u8] {
        &self.inner.session_id
    }

    /// Hash-to-curve domain tag.
    pub fn h2c_domain(&self) -> &[u8] {
        &self.inner.h2c_domain
    }

    /// Aggregate OPRF public key.
    pub fn public_key(&self) -> &OprfPublicKey {
        &self.inner.public_key
    }

    /// Pedersen parameters used for the client-side commitment.
    pub fn pedersen(&self) -> &PedersenParams {
        &self.inner.pedersen
    }

    /// Returns `true` if this scheme can perform FULL tag-origin
    /// validation (i.e., it holds the OPRF secret key). Production
    /// threshold deployments return `false` — they must call
    /// `verify_tag_with_secret_key` via a threshold re-combine at
    /// spend time instead.
    pub fn can_verify_tag_origin(&self) -> bool {
        self.inner.secret_key.is_some()
    }
}

/// Builder-style configuration for [`SbtScheme::new`].
#[derive(Debug)]
pub struct SbtSchemeConfig {
    /// Pedersen parameters for the client-side commitment.
    pub pedersen: PedersenParams,
    /// Per-trustee public commitments. Must contain at least
    /// `threshold` entries with unique non-zero 1-based indices and
    /// non-identity commits.
    pub commits: Vec<OprfServerCommit>,
    /// Reconstruction threshold. Must be between 1 and `commits.len()`.
    pub threshold: usize,
    /// Hash-to-curve domain tag. Must be non-empty.
    pub h2c_domain: Vec<u8>,
    /// Session id; must be at least `MIN_SESSION_ID_LEN` bytes.
    pub session_id: Vec<u8>,
    /// Client master secret used to blind the deterministic `(s, r)`
    /// derivation. Must be high-entropy.
    pub client_secret: [u8; 32],
    /// Expected aggregate OPRF public key `Y = G · k`. If provided,
    /// `new()` cross-checks this against the Lagrange combine of
    /// two disjoint quorums, rejecting if they disagree. Callers
    /// should populate this from their DKG output (the constant
    /// term of the shared polynomial). When `None`, the aggregate
    /// is derived from `commits` and trusted unconditionally — use
    /// ONLY in tests.
    pub expected_public_key: Option<OprfPublicKey>,
    /// Held OPRF secret key for full tag-origin validation. Only
    /// used in tests / centralized deployments. Production threshold
    /// nodes leave this `None`.
    pub secret_key: Option<Scalar>,
}

impl SbtScheme {
    /// Validate the config and construct a scheme.
    ///
    /// Checks:
    /// - All commits are structurally valid (non-zero index,
    ///   non-identity commit point).
    /// - Commit indices are unique.
    /// - `threshold <= commits.len()` and `threshold >= 1`.
    /// - `session_id.len() >= MIN_SESSION_ID_LEN`.
    /// - `h2c_domain` is non-empty.
    /// - If `expected_public_key` is provided, the aggregate computed
    ///   via Lagrange over *two disjoint quorums* matches it. This
    ///   closes M-3 (caller-ordering trust) by forcing the caller to
    ///   commit to the DKG's `f(0)·G` value out-of-band.
    /// - If `secret_key` is provided, verify that `G·k` matches the
    ///   aggregate public key.
    pub fn new(config: SbtSchemeConfig) -> Result<Self, SbtError> {
        let SbtSchemeConfig {
            pedersen,
            commits,
            threshold,
            h2c_domain,
            session_id,
            client_secret,
            expected_public_key,
            secret_key,
        } = config;

        if threshold == 0 || threshold > commits.len() {
            return Err(SbtError::Insufficient {
                got: commits.len(),
                need: threshold,
            });
        }
        if session_id.len() < MIN_SESSION_ID_LEN {
            return Err(SbtError::SessionTooShort);
        }
        if h2c_domain.is_empty() {
            return Err(SbtError::EmptyDomain);
        }
        // Dedup and per-entry structural checks.
        let mut seen = std::collections::BTreeSet::new();
        for c in &commits {
            c.validate()?;
            if !seen.insert(c.index) {
                return Err(SbtError::DuplicateIndex(c.index));
            }
        }

        // Lagrange-combine the first `threshold` commits at x=0. The
        // uniqueness of Shamir sharing guarantees this equals
        // `f(0)·G` regardless of quorum choice.
        let agg1 = aggregate_over_quorum(&commits[..threshold])?;

        // If we have at least `2·threshold` commits, cross-check
        // against a SECOND disjoint quorum. If they disagree, the
        // commits vector was not produced by a single consistent
        // DKG run and the aggregate is unreliable.
        let has_disjoint_quorum = commits.len() >= 2 * threshold;
        if has_disjoint_quorum {
            let agg2 = aggregate_over_quorum(&commits[threshold..2 * threshold])?;
            if agg1 != agg2 {
                return Err(SbtError::AggregateMismatch);
            }
        }

        // If we cannot cross-check, the caller MUST pin the aggregate
        // out-of-band via `expected_public_key`. Otherwise a
        // malicious commits vector could inject any aggregate Y.
        if !has_disjoint_quorum && expected_public_key.is_none() {
            return Err(SbtError::AggregateMismatch);
        }

        if agg1 == RistrettoPoint::default() {
            return Err(SbtError::IdentityPoint);
        }

        // If the caller supplied an expected public key, require it
        // to match what we computed.
        if let Some(expected) = &expected_public_key {
            if expected.0 != agg1 {
                return Err(SbtError::AggregateMismatch);
            }
        }

        let public_key = OprfPublicKey(agg1);

        // If a secret key was supplied, cross-check against the
        // aggregate public key.
        if let Some(sk) = &secret_key {
            let expected = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * sk;
            if expected != agg1 {
                return Err(SbtError::AggregateMismatch);
            }
        }

        Ok(Self {
            inner: SbtSchemeInner {
                pedersen,
                commits,
                threshold,
                h2c_domain,
                session_id,
                public_key,
                client_secret,
                secret_key,
            },
        })
    }
}

/// Lagrange-combine a set of commits at x=0 to recover `f(0)·G`.
fn aggregate_over_quorum(
    quorum: &[OprfServerCommit],
) -> Result<RistrettoPoint, SbtError> {
    let indices: Vec<u32> = quorum.iter().map(|c| c.index).collect();
    let mut agg = RistrettoPoint::default();
    for c in quorum {
        let lambda = crate::oprf::lagrange_coefficient(c.index, &indices)?;
        agg += c.commit * lambda;
    }
    Ok(agg)
}

/// Client-side secret state between `prepare` and `finalize`.
pub struct SbtClientState {
    /// Pedersen-commitment opening: secret payload.
    pub s: Scalar,
    /// Pedersen-commitment opening: blinding.
    pub r: Scalar,
    /// Commitment point `C = g·s + h·r`.
    pub commitment: RistrettoPoint,
    /// OPRF blinding state (includes `α`, `α⁻¹`, and the H2C base).
    pub oprf_state: OprfBlinding,
}

impl Zeroize for SbtClientState {
    fn zeroize(&mut self) {
        self.s.zeroize();
        self.r.zeroize();
        // OprfBlinding has its own ZeroizeOnDrop so we don't need to
        // reach into its fields; but for robustness against a future
        // refactor that moves the state out of Drop, do the explicit
        // zeroize on its secret fields too.
        self.oprf_state.alpha.zeroize();
        self.oprf_state.alpha_inv.zeroize();
        // `commitment` and `oprf_state.base` are public inputs — no
        // need to zeroize, but the secret scalars above are gone.
    }
}

impl Drop for SbtClientState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Client → signer request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SbtRequest {
    /// Pedersen commitment `C`.
    pub commitment: RistrettoPoint,
    /// Blinded OPRF input `B = H2C(C) · α`.
    pub blinded: RistrettoPoint,
    /// Session id under which this request was issued.
    pub session_id: Vec<u8>,
}

impl SbtRequest {
    /// Validate structural invariants: non-identity points, session
    /// id is long enough.
    pub fn validate(&self) -> Result<(), SbtError> {
        let identity = RistrettoPoint::default();
        if self.commitment == identity || self.blinded == identity {
            return Err(SbtError::IdentityPoint);
        }
        if self.session_id.len() < MIN_SESSION_ID_LEN {
            return Err(SbtError::SessionTooShort);
        }
        Ok(())
    }
}

/// The final SBT token returned by the mint interaction. Holds the
/// Pedersen commitment, the OPRF tag `T = P·k`, and a NIZK that the
/// client knows the commitment opening AND that the tag was derived
/// from `H2C(C)` (via the transcript binding inside `TokenProof`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendToken {
    /// Pedersen commitment `C`.
    pub commitment: RistrettoPoint,
    /// OPRF tag `T = H2C(C) · k`.
    pub tag: RistrettoPoint,
    /// NIZK proof of knowledge of `(s, r)` bound to `(C, H2C(C), T)`
    /// and the aggregate OPRF public key `Y`.
    pub proof: TokenProof,
    /// Session id under which the token was minted.
    pub session_id: Vec<u8>,
}

impl SpendToken {
    /// Derive the SBT-specific nullifier.
    ///
    /// Returns a typed [`SbtNullifier`] rather than a raw `[u8; 32]`
    /// so it cannot be accidentally cross-fed into the classical PCT
    /// `specter-core::nullifier::compute_nullifier` output space
    /// (which uses the domain tag `"specter-nullifier:"` and a
    /// different wire format). Both systems' outputs are 32 bytes
    /// drawn from SHAKE-256 with distinct domain tags, so they are
    /// cryptographically independent at the ROM level, but a future
    /// refactor that forgets the domain tag would silently collide
    /// the two namespaces. The newtype is an additional
    /// defense-in-depth layer.
    ///
    /// Computed as
    /// `SHAKE-256("SPECTER-SBT-NULL-v1/" || u64_be(len(tag)) || tag)[..32]`.
    pub fn nullifier(&self) -> SbtNullifier {
        let mut h = Shake256::default();
        h.update(b"SPECTER-SBT-NULL-v1/");
        let tag_bytes = self.tag.compress().to_bytes();
        h.update(&(tag_bytes.len() as u64).to_be_bytes());
        h.update(&tag_bytes);
        let mut out = [0u8; 32];
        h.finalize_xof().read(&mut out);
        SbtNullifier(out)
    }

    /// Validate structural invariants: non-identity points and
    /// long-enough session id.
    pub fn validate(&self) -> Result<(), SbtError> {
        let identity = RistrettoPoint::default();
        if self.tag == identity || self.commitment == identity {
            return Err(SbtError::IdentityPoint);
        }
        if self.session_id.len() < MIN_SESSION_ID_LEN {
            return Err(SbtError::SessionTooShort);
        }
        Ok(())
    }
}

impl BlindSignatureScheme for SbtScheme {
    type ClientState = SbtClientState;
    type ClientRequest = SbtRequest;
    type ServerResponse = OprfEvaluation;
    type Token = SpendToken;
    type Error = SbtError;

    fn prepare<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        payload: &[u8],
    ) -> Result<(Self::ClientState, Self::ClientRequest), Self::Error> {
        // `(s, r)` is deterministic in `(client_secret, payload)` so
        // (a) two mints of the same payload by the same client
        // produce the same nullifier (double-spend detection) and
        // (b) the commitment stays hiding against any observer who
        // does not know `client_secret`.
        let s = derive_scalar(b"sbt-payload-s", &self.inner.client_secret, payload);
        let r = derive_scalar(b"sbt-payload-r", &self.inner.client_secret, payload);
        let commitment = self.inner.pedersen.g * s + self.inner.pedersen.h * r;

        // Blind the commitment compressed-bytes representation into
        // the OPRF. This ties `B` to `C` so the H2C base can be
        // recomputed by the verifier from `C` alone.
        let c_bytes = commitment.compress().to_bytes();
        let (oprf_state, blinded) = blind(rng, &self.inner.h2c_domain, &c_bytes)?;

        let state = SbtClientState {
            s,
            r,
            commitment,
            oprf_state,
        };
        let req = SbtRequest {
            commitment,
            blinded,
            session_id: self.inner.session_id.clone(),
        };
        req.validate()?;
        Ok((state, req))
    }

    fn finalize<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        state: Self::ClientState,
        request: &Self::ClientRequest,
        responses: &[Self::ServerResponse],
    ) -> Result<Self::Token, Self::Error> {
        // Structural validation first.
        request.validate()?;
        // Session id MUST match the scheme's canonical session id.
        if request.session_id.ct_eq(&self.inner.session_id).unwrap_u8() == 0 {
            return Err(SbtError::SessionMismatch);
        }
        // Cross-check that the request matches the state that
        // produced it.
        if request.commitment != state.commitment {
            return Err(SbtError::StateRequestMismatch);
        }
        if request.blinded != state.oprf_state.blinded() {
            return Err(SbtError::StateRequestMismatch);
        }

        // Validate every server response structurally.
        for r in responses {
            r.validate()?;
        }

        // Combine the threshold evaluations under the scheme's
        // canonical session id.
        let bk = combine_evaluations(
            self.inner.threshold,
            &self.inner.commits,
            responses,
            &request.blinded,
            &self.inner.session_id,
        )?;
        // Unblind.
        let tag = unblind(&state.oprf_state, &bk);
        if tag == RistrettoPoint::default() {
            return Err(SbtError::IdentityPoint);
        }

        // Build the NIZK. Aggregate public key `Y` is bound into
        // the transcript to prevent cross-key replay.
        let p = hash_to_curve(
            &self.inner.h2c_domain,
            &state.commitment.compress().to_bytes(),
        );
        let proof = TokenProof::prove(
            rng,
            &self.inner.pedersen,
            &state.commitment,
            &p,
            &tag,
            &state.s,
            &state.r,
            &self.inner.session_id,
            &self.inner.public_key.0,
        );
        Ok(SpendToken {
            commitment: state.commitment,
            tag,
            proof,
            session_id: self.inner.session_id.clone(),
        })
    }

    /// Verify a spent token. Performs:
    /// - Structural validation.
    /// - Session consistency.
    /// - Client-side Schnorr PoK of the Pedersen commitment opening.
    /// - **If and only if the scheme holds a `secret_key`**, the
    ///   full tag-origin check `tag == H2C(C)·k`.
    ///
    /// If the scheme does NOT hold a `secret_key`, this method returns
    /// `Err(SbtError::TagOriginCheckRequired)` so the caller is
    /// forced to handle tag-origin verification explicitly — via
    /// a threshold re-combine at spend time. This is a conservative
    /// default: we refuse to accept a token we cannot fully verify
    /// rather than silently returning an incomplete `Ok(())`.
    ///
    /// **Side-channel note**: all cryptographic checks are run
    /// unconditionally and their outcomes collapsed into a single
    /// error variant at the end, so a remote attacker cannot
    /// distinguish which step failed based on the returned error.
    /// The `TagOriginCheckRequired` short-circuit is intentional
    /// because it's a configuration issue, not a token content
    /// check, so no attacker-controlled oracle leak arises from it.
    fn verify_token(&self, token: &Self::Token) -> Result<(), Self::Error> {
        // Short-circuit on configuration: if the scheme cannot do a
        // full check, tell the caller loudly so they know to run
        // `verify_tag_with_secret_key` via a threshold helper.
        let Some(k) = self.inner.secret_key.as_ref() else {
            return Err(SbtError::TagOriginCheckRequired);
        };

        // Run every check unconditionally. We *want* constant-time-ish
        // behavior on token inputs: accumulate the conjunction, then
        // decide at the very end.
        let structural = token.validate().is_ok();
        let session_ok =
            token.session_id.ct_eq(&self.inner.session_id).unwrap_u8() == 1;
        let proof_ok = self.verify_client_proof_internal(token).is_ok();
        let tag_ok = self.verify_tag_with_secret_key(token, k).is_ok();

        if structural && session_ok && proof_ok && tag_ok {
            Ok(())
        } else {
            // Collapse all failure cases into the same variant so the
            // caller cannot distinguish which check failed. Structural
            // oddness is visible via direct `token.validate()` if the
            // caller wants it.
            Err(SbtError::TokenProofFailed)
        }
    }
}

impl SbtScheme {
    /// Verify the client-side Schnorr PoK portion of a token. Does
    /// NOT verify tag origin — see [`SbtScheme::verify_tag_with_secret_key`].
    ///
    /// Exposed publicly so a threshold spend verifier can run the
    /// client proof check once and then decide how to validate tag
    /// origin (via `verify_tag_with_secret_key` in a threshold
    /// re-combine, or via a future pairing-based construction).
    pub fn verify_client_proof(&self, token: &SpendToken) -> Result<(), SbtError> {
        token.validate()?;
        if token.session_id.ct_eq(&self.inner.session_id).unwrap_u8() == 0 {
            return Err(SbtError::SessionMismatch);
        }
        self.verify_client_proof_internal(token)
    }

    /// Inner helper used by both `verify_token` and `verify_client_proof`
    /// so the session-id check is done once at the entry point.
    fn verify_client_proof_internal(&self, token: &SpendToken) -> Result<(), SbtError> {
        let p = hash_to_curve(
            &self.inner.h2c_domain,
            &token.commitment.compress().to_bytes(),
        );
        if p == RistrettoPoint::default() {
            return Err(SbtError::IdentityPoint);
        }
        token
            .proof
            .verify(
                &self.inner.pedersen,
                &token.commitment,
                &p,
                &token.tag,
                &self.inner.session_id,
                &self.inner.public_key.0,
            )
            .map_err(|_| SbtError::TokenProofFailed)
    }

    /// **Tag-origin validation** — checks that `token.tag = P·k`
    /// where `P = H2C(h2c_domain, commitment_bytes)` for the provided
    /// secret key `k`. Production deployments reach this path via
    /// either a centralized mint rerunning the check or a threshold
    /// OPRF round over `P` at spend time.
    pub fn verify_tag_with_secret_key(
        &self,
        token: &SpendToken,
        k: &Scalar,
    ) -> Result<(), SbtError> {
        token.validate()?;
        let p = hash_to_curve(
            &self.inner.h2c_domain,
            &token.commitment.compress().to_bytes(),
        );
        let expected = p * k;
        // Constant-time compare of compressed bytes.
        if expected
            .compress()
            .as_bytes()
            .ct_eq(token.tag.compress().as_bytes())
            .unwrap_u8()
            == 0
        {
            return Err(SbtError::TagOriginMismatch);
        }
        Ok(())
    }

    /// Verify tag-origin via threshold re-evaluation at spend time.
    ///
    /// Each validator calls [`evaluate_for_spend`](Self::evaluate_for_spend)
    /// on `P = H2C(C)` (the UNBLINDED commitment hash) with its
    /// share `k_i`, producing `T'_i = P·k_i` plus a DDH proof. The
    /// caller collects a quorum of these evaluations and passes them
    /// here. This function:
    ///   1. Calls `combine_evaluations` over the unblinded base `P`.
    ///   2. Compares the result `T'` to `token.tag` in constant time.
    ///   3. Also runs `verify_client_proof` on the token.
    ///
    /// The `spend_session_id` MUST be distinct from the mint-time
    /// `session_id` to prevent cross-protocol replay of mint-time
    /// DDH proofs. It must also be at least `MIN_SESSION_ID_LEN`
    /// bytes.
    pub fn verify_tag_threshold(
        &self,
        token: &SpendToken,
        evaluations: &[OprfEvaluation],
        spend_session_id: &[u8],
    ) -> Result<(), SbtError> {
        token.validate()?;
        if spend_session_id.len() < MIN_SESSION_ID_LEN {
            return Err(SbtError::SessionTooShort);
        }
        // Prevent accidental reuse of mint-time session.
        if spend_session_id == self.inner.session_id.as_slice() {
            return Err(SbtError::SessionMismatch);
        }

        // Verify client proof first.
        if token.session_id.ct_eq(&self.inner.session_id).unwrap_u8() == 0 {
            return Err(SbtError::SessionMismatch);
        }
        self.verify_client_proof_internal(token)?;

        // Recompute P = H2C(C) — the UNBLINDED base point.
        let p = hash_to_curve(
            &self.inner.h2c_domain,
            &token.commitment.compress().to_bytes(),
        );
        if p == RistrettoPoint::default() {
            return Err(SbtError::IdentityPoint);
        }

        // Combine the threshold evaluations. The spend-time session
        // binds each DDH proof to this specific verification round.
        let t_prime = combine_evaluations(
            self.inner.threshold,
            &self.inner.commits,
            evaluations,
            &p,
            spend_session_id,
        )?;

        // Constant-time compare.
        if t_prime
            .compress()
            .as_bytes()
            .ct_eq(token.tag.compress().as_bytes())
            .unwrap_u8()
            == 0
        {
            return Err(SbtError::TagOriginMismatch);
        }
        Ok(())
    }

    /// Validator helper: compute a spend-time OPRF evaluation on the
    /// unblinded `H2C(C)` point. Called by each validator holding a
    /// share `(k_i, Y_i)`. The returned `OprfEvaluation` is sent to
    /// the spend verifier who calls [`verify_tag_threshold`](Self::verify_tag_threshold).
    pub fn evaluate_for_spend<R: CryptoRng + RngCore>(
        rng: &mut R,
        token: &SpendToken,
        share: &OprfSecretShare,
        commit: &OprfServerCommit,
        h2c_domain: &[u8],
        spend_session_id: &[u8],
    ) -> Result<OprfEvaluation, SbtError> {
        let p = hash_to_curve(h2c_domain, &token.commitment.compress().to_bytes());
        if p == RistrettoPoint::default() {
            return Err(SbtError::IdentityPoint);
        }
        crate::oprf::evaluate_server(rng, share, commit, &p, spend_session_id)
    }
}

/// Crate-wide domain tag for the `(s, r)` KDF. Distinct from the
/// transcript tag in [`crate::transcript::SBT_TRANSCRIPT_TAG`] so
/// the two subsystems can version independently. The `v2` suffix
/// marks that this path now mixes in `client_secret` (compared to
/// the `v1` scheme that hashed only the payload).
pub const SBT_KDF_TAG: &[u8] = b"SPECTER-SBT-KDF-v2/";

/// Deterministically derive a Scalar from `(domain, client_secret,
/// payload)` via SHAKE-256. Used for both the committed value `s`
/// and the blinding factor `r`, with distinct domain tags so no
/// observer can recover a useful relation between them.
///
/// The `client_secret` input is critical for the commitment hiding
/// property: without it, `(s, r)` and thus `C` would be a public
/// function of the payload alone, defeating hiding.
fn derive_scalar(domain: &'static [u8], client_secret: &[u8; 32], payload: &[u8]) -> Scalar {
    let mut h = Shake256::default();
    h.update(SBT_KDF_TAG);
    h.update(&(domain.len() as u64).to_be_bytes());
    h.update(domain);
    h.update(&(client_secret.len() as u64).to_be_bytes());
    h.update(client_secret);
    h.update(&(payload.len() as u64).to_be_bytes());
    h.update(payload);
    let mut buf = [0u8; 64];
    h.finalize_xof().read(&mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oprf::{evaluate_server, OprfSecretShare};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
    use rand::rngs::OsRng;

    fn build_scheme_3_of_5() -> (SbtScheme, Vec<OprfSecretShare>, Scalar) {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        // Random polynomial of degree t-1 with a_0 = k.
        let t = 3usize;
        let n: u32 = 5;
        let mut coeffs = vec![k];
        for _ in 1..t {
            coeffs.push(Scalar::random(&mut rng));
        }
        let mut shares = Vec::new();
        let mut commits = Vec::new();
        for i in 1..=n {
            let x = Scalar::from(i as u64);
            let mut y = Scalar::ZERO;
            let mut xp = Scalar::ONE;
            for c in &coeffs {
                y += c * xp;
                xp *= x;
            }
            shares.push(OprfSecretShare {
                index: i,
                scalar: y,
            });
            commits.push(OprfServerCommit {
                index: i,
                commit: G * y,
            });
        }

        let mut client_secret = [0u8; 32];
        for b in &mut client_secret {
            *b = rand::random::<u8>();
        }
        let scheme = SbtScheme::new(SbtSchemeConfig {
            pedersen: PedersenParams::new(),
            commits,
            threshold: t,
            h2c_domain: b"specter-sbt-mint".to_vec(),
            session_id: b"epoch-1:nonce-abcdef012345".to_vec(),
            client_secret,
            expected_public_key: Some(OprfPublicKey(G * k)),
            secret_key: Some(k),
        })
        .unwrap();
        (scheme, shares, k)
    }

    #[test]
    fn aggregate_public_key_matches_k_times_g() {
        let (scheme, _shares, k) = build_scheme_3_of_5();
        let expected = G * k;
        assert_eq!(scheme.public_key().0, expected);
    }

    #[test]
    fn new_rejects_duplicate_indices() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let commit = OprfServerCommit {
            index: 1,
            commit: G * k,
        };
        let cfg = SbtSchemeConfig {
            pedersen: PedersenParams::new(),
            commits: vec![commit.clone(), commit.clone(), commit],
            threshold: 2,
            h2c_domain: b"d".to_vec(),
            session_id: b"session-id-of-at-least-16-bytes".to_vec(),
            client_secret: [0u8; 32],
            expected_public_key: None,
            secret_key: None,
        };
        assert!(matches!(
            SbtScheme::new(cfg),
            Err(SbtError::DuplicateIndex(1))
        ));
    }

    #[test]
    fn new_rejects_empty_domain() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let cfg = SbtSchemeConfig {
            pedersen: PedersenParams::new(),
            commits: vec![OprfServerCommit {
                index: 1,
                commit: G * k,
            }],
            threshold: 1,
            h2c_domain: vec![],
            session_id: b"session-id-of-at-least-16-bytes".to_vec(),
            client_secret: [0u8; 32],
            expected_public_key: None,
            secret_key: None,
        };
        assert!(matches!(SbtScheme::new(cfg), Err(SbtError::EmptyDomain)));
    }

    #[test]
    fn new_rejects_short_session() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let cfg = SbtSchemeConfig {
            pedersen: PedersenParams::new(),
            commits: vec![OprfServerCommit {
                index: 1,
                commit: G * k,
            }],
            threshold: 1,
            h2c_domain: b"d".to_vec(),
            session_id: b"short".to_vec(),
            client_secret: [0u8; 32],
            expected_public_key: None,
            secret_key: None,
        };
        assert!(matches!(SbtScheme::new(cfg), Err(SbtError::SessionTooShort)));
    }

    #[test]
    fn new_rejects_threshold_above_count() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let cfg = SbtSchemeConfig {
            pedersen: PedersenParams::new(),
            commits: vec![OprfServerCommit {
                index: 1,
                commit: G * k,
            }],
            threshold: 5,
            h2c_domain: b"d".to_vec(),
            session_id: b"session-id-of-at-least-16-bytes".to_vec(),
            client_secret: [0u8; 32],
            expected_public_key: None,
            secret_key: None,
        };
        assert!(matches!(
            SbtScheme::new(cfg),
            Err(SbtError::Insufficient { .. })
        ));
    }

    #[test]
    fn new_rejects_identity_commit() {
        let cfg = SbtSchemeConfig {
            pedersen: PedersenParams::new(),
            commits: vec![OprfServerCommit {
                index: 1,
                commit: RistrettoPoint::default(),
            }],
            threshold: 1,
            h2c_domain: b"d".to_vec(),
            session_id: b"session-id-of-at-least-16-bytes".to_vec(),
            client_secret: [0u8; 32],
            expected_public_key: None,
            secret_key: None,
        };
        assert!(matches!(SbtScheme::new(cfg), Err(SbtError::IdentityPoint)));
    }

    #[test]
    fn end_to_end_roundtrip() {
        let (scheme, shares, k) = build_scheme_3_of_5();

        let payload = b"my secret 32-byte-or-whatever payload";
        let (state, req) = scheme.prepare(&mut OsRng, payload).unwrap();

        let responses: Vec<_> = (0..3)
            .map(|i| {
                evaluate_server(
                    &mut OsRng,
                    &shares[i],
                    &scheme.commits()[i],
                    &req.blinded,
                    scheme.session_id(),
                )
                .unwrap()
            })
            .collect();

        let token = scheme.finalize(&mut OsRng, state, &req, &responses).unwrap();
        // Client-side proof check.
        scheme.verify_token(&token).unwrap();
        // Tag-origin check using the held secret key.
        scheme.verify_tag_with_secret_key(&token, &k).unwrap();

        // Nullifier is deterministic for the same token.
        let n1 = token.nullifier();
        let n2 = token.nullifier();
        assert_eq!(n1, n2);
    }

    #[test]
    fn tag_origin_rejects_wrong_key() {
        let (scheme, shares, _k) = build_scheme_3_of_5();
        let (state, req) = scheme.prepare(&mut OsRng, b"payload").unwrap();
        let responses: Vec<_> = (0..3)
            .map(|i| {
                evaluate_server(
                    &mut OsRng,
                    &shares[i],
                    &scheme.commits()[i],
                    &req.blinded,
                    scheme.session_id(),
                )
                .unwrap()
            })
            .collect();
        let token = scheme.finalize(&mut OsRng, state, &req, &responses).unwrap();

        // A random k' must NOT pass tag-origin verification.
        let k_prime = Scalar::random(&mut OsRng);
        let res = scheme.verify_tag_with_secret_key(&token, &k_prime);
        assert!(matches!(res, Err(SbtError::TagOriginMismatch)));
    }

    #[test]
    fn same_payload_same_nullifier() {
        let (scheme, shares, _k) = build_scheme_3_of_5();

        let payload = b"fixed-payload";

        let mk_token = |picks: &[usize]| -> SpendToken {
            let (state, req) = scheme.prepare(&mut OsRng, payload).unwrap();
            let responses: Vec<_> = picks
                .iter()
                .map(|&i| {
                    evaluate_server(
                        &mut OsRng,
                        &shares[i],
                        &scheme.commits()[i],
                        &req.blinded,
                        scheme.session_id(),
                    )
                    .unwrap()
                })
                .collect();
            scheme
                .finalize(&mut OsRng, state, &req, &responses)
                .unwrap()
        };

        let t1 = mk_token(&[0, 1, 2]);
        let t2 = mk_token(&[0, 2, 4]);
        let t3 = mk_token(&[1, 3, 4]);

        assert_eq!(t1.nullifier(), t2.nullifier());
        assert_eq!(t2.nullifier(), t3.nullifier());
        assert_eq!(t1.commitment, t2.commitment);
    }

    #[test]
    fn distinct_payloads_distinct_nullifiers() {
        let (scheme, shares, _k) = build_scheme_3_of_5();

        let mk_nullifier = |p: &[u8]| -> SbtNullifier {
            let (state, req) = scheme.prepare(&mut OsRng, p).unwrap();
            let responses: Vec<_> = (0..3)
                .map(|i| {
                    evaluate_server(
                        &mut OsRng,
                        &shares[i],
                        &scheme.commits()[i],
                        &req.blinded,
                        scheme.session_id(),
                    )
                    .unwrap()
                })
                .collect();
            let token = scheme.finalize(&mut OsRng, state, &req, &responses).unwrap();
            token.nullifier()
        };

        let n1 = mk_nullifier(b"payload-A");
        let n2 = mk_nullifier(b"payload-B");
        assert_ne!(n1, n2);
    }

    #[test]
    fn distinct_client_secrets_give_distinct_commitments() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let mk_scheme = |secret: [u8; 32]| -> SbtScheme {
            let mut coeffs = vec![k];
            for _ in 1..3 {
                coeffs.push(Scalar::random(&mut OsRng));
            }
            let mut commits = Vec::new();
            for i in 1..=5u32 {
                let x = Scalar::from(i as u64);
                let mut y = Scalar::ZERO;
                let mut xp = Scalar::ONE;
                for c in &coeffs {
                    y += c * xp;
                    xp *= x;
                }
                commits.push(OprfServerCommit {
                    index: i,
                    commit: G * y,
                });
            }
            SbtScheme::new(SbtSchemeConfig {
                pedersen: PedersenParams::new(),
                commits,
                threshold: 3,
                h2c_domain: b"d".to_vec(),
                session_id: b"session-id-long-enough".to_vec(),
                client_secret: secret,
                expected_public_key: Some(OprfPublicKey(G * k)),
                secret_key: Some(k),
            })
            .unwrap()
        };

        let s1 = mk_scheme([1u8; 32]);
        let s2 = mk_scheme([2u8; 32]);

        let (state1, req1) = s1.prepare(&mut OsRng, b"payload").unwrap();
        let (state2, req2) = s2.prepare(&mut OsRng, b"payload").unwrap();
        assert_ne!(req1.commitment, req2.commitment);
        let _ = (state1, state2);
    }

    #[test]
    fn tampered_token_rejected() {
        let (scheme, shares, _k) = build_scheme_3_of_5();
        let (state, req) = scheme.prepare(&mut OsRng, b"payload").unwrap();

        let responses: Vec<_> = (0..3)
            .map(|i| {
                evaluate_server(
                    &mut OsRng,
                    &shares[i],
                    &scheme.commits()[i],
                    &req.blinded,
                    scheme.session_id(),
                )
                .unwrap()
            })
            .collect();

        let mut token = scheme.finalize(&mut OsRng, state, &req, &responses).unwrap();
        // Swap the tag for a different random point.
        token.tag = G * Scalar::random(&mut OsRng);
        let res = scheme.verify_token(&token);
        assert!(res.is_err());
    }

    #[test]
    fn insufficient_responses_rejected() {
        let (scheme, shares, _k) = build_scheme_3_of_5();
        let (state, req) = scheme.prepare(&mut OsRng, b"payload").unwrap();

        // Only 2 responses for threshold 3.
        let responses: Vec<_> = (0..2)
            .map(|i| {
                evaluate_server(
                    &mut OsRng,
                    &shares[i],
                    &scheme.commits()[i],
                    &req.blinded,
                    scheme.session_id(),
                )
                .unwrap()
            })
            .collect();

        let res = scheme.finalize(&mut OsRng, state, &req, &responses);
        assert!(matches!(res, Err(SbtError::Insufficient { .. })));
    }

    #[test]
    fn wrong_session_id_rejected() {
        let (scheme, shares, _k) = build_scheme_3_of_5();
        let (state, req) = scheme.prepare(&mut OsRng, b"payload").unwrap();

        let responses: Vec<_> = (0..3)
            .map(|i| {
                evaluate_server(
                    &mut OsRng,
                    &shares[i],
                    &scheme.commits()[i],
                    &req.blinded,
                    b"different-session-id",
                )
                .unwrap()
            })
            .collect();

        let res = scheme.finalize(&mut OsRng, state, &req, &responses);
        assert!(res.is_err());
    }

    #[test]
    fn malicious_trustee_fails_chaum_pedersen() {
        let (scheme, shares, _k) = build_scheme_3_of_5();
        let (state, req) = scheme.prepare(&mut OsRng, b"payload").unwrap();

        let mut responses: Vec<_> = (0..3)
            .map(|i| {
                evaluate_server(
                    &mut OsRng,
                    &shares[i],
                    &scheme.commits()[i],
                    &req.blinded,
                    scheme.session_id(),
                )
                .unwrap()
            })
            .collect();

        // Malicious trustee injects a different scalar.
        let bad_scalar = Scalar::random(&mut OsRng);
        responses[1].point = req.blinded * bad_scalar;

        let res = scheme.finalize(&mut OsRng, state, &req, &responses);
        assert!(matches!(res, Err(SbtError::DdhEqualityFailed(_))));
    }
}
