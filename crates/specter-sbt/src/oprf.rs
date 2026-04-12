//! DH-OPRF core (2HashDH flavor) with threshold evaluation.
//!
//! The OPRF key `k ∈ Z_l` is shared across `n` trustees using Shamir
//! secret sharing (the same Feldman-VSS setup the existing blind-sig
//! code uses). A client blinds its message, each trustee evaluates,
//! then the client Lagrange-combines the shares.
//!
//! Every share exchange carries a **Chaum-Pedersen DDH-equality NIZK**
//! proving that the trustee used the same scalar `k_i` as the one
//! committed to in its published share commitment `Y_i = G · k_i`.
//! This stops a rogue trustee from returning `B · k_i'` for some
//! `k_i' ≠ k_i` — an attack that would otherwise poison the Lagrange
//! reconstruction without detection.

use crate::proof::DdhEqualityProof;
use crate::SbtError;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The public OPRF key. `Y = G · k`, where `k` is the (un-shared)
/// OPRF scalar. In a threshold setup `Y = Σ_i λ_i · Y_i` for any
/// quorum — or simply the group commitment from the VSS.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OprfPublicKey(pub RistrettoPoint);

impl OprfPublicKey {
    /// Validate that this key does not contain an identity point,
    /// which would correspond to the zero scalar.
    pub fn validate(&self) -> Result<(), SbtError> {
        if self.0 == RistrettoPoint::default() {
            return Err(SbtError::IdentityPoint);
        }
        Ok(())
    }
}

/// One trustee's share of the OPRF key. Zeroized on drop.
///
/// `index` is the 1-based Shamir index, `scalar` is `k_i = f(index)`
/// for the secret polynomial `f`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OprfSecretShare {
    /// 1-based Shamir index.
    #[zeroize(skip)]
    pub index: u32,
    /// The share scalar.
    pub scalar: Scalar,
}

impl std::fmt::Debug for OprfSecretShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OprfSecretShare")
            .field("index", &self.index)
            .field("scalar", &"<redacted>")
            .finish()
    }
}

/// Per-trustee public commitment `Y_i = G · k_i`. Published at DKG
/// time; the client uses it to verify the DDH-equality proof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OprfServerCommit {
    /// 1-based Shamir index.
    pub index: u32,
    /// `Y_i = G · k_i`.
    pub commit: RistrettoPoint,
}

impl OprfServerCommit {
    /// Validate on the wire: reject index 0 and identity commits.
    pub fn validate(&self) -> Result<(), SbtError> {
        if self.index == 0 {
            return Err(SbtError::InvalidIndex(0));
        }
        if self.commit == RistrettoPoint::default() {
            return Err(SbtError::IdentityPoint);
        }
        Ok(())
    }
}

/// Client-side blinding state. **Never send this over the wire.** The
/// scalar `alpha` is the blinding factor; `alpha_inv` is cached so
/// unblinding is one scalar-mult. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OprfBlinding {
    pub(crate) alpha: Scalar,
    pub(crate) alpha_inv: Scalar,
    /// The unblinded hash-to-curve point `P = H2C(message)`. Kept so
    /// the verifier can recover `B = P·α` internally without storing
    /// the blinded point separately.
    #[zeroize(skip)]
    pub(crate) base: RistrettoPoint,
}

impl std::fmt::Debug for OprfBlinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OprfBlinding")
            .field("alpha", &"<redacted>")
            .field("base", &self.base.compress())
            .finish()
    }
}

impl OprfBlinding {
    /// Return the blinded point `B = P · α` that the client sends to
    /// each trustee.
    pub fn blinded(&self) -> RistrettoPoint {
        self.base * self.alpha
    }
}

/// One trustee's evaluation of the blinded point plus a NIZK proving
/// the trustee used the correct share.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OprfEvaluation {
    /// 1-based Shamir index of the trustee.
    pub index: u32,
    /// `B_i = B · k_i`.
    pub point: RistrettoPoint,
    /// Chaum-Pedersen DDH-equality proof of `log_G(Y_i) = log_B(B_i)`.
    pub proof: DdhEqualityProof,
}

impl OprfEvaluation {
    /// Validate structural invariants on the wire: reject index 0
    /// and identity points.
    pub fn validate(&self) -> Result<(), SbtError> {
        if self.index == 0 {
            return Err(SbtError::InvalidIndex(0));
        }
        if self.point == RistrettoPoint::default() {
            return Err(SbtError::IdentityPoint);
        }
        Ok(())
    }
}

/// Hash-to-curve for the SBT OPRF.
///
/// Uses curve25519-dalek's `RistrettoPoint::hash_from_bytes::<Sha512>`,
/// which folds 64 bytes of hash output into two `from_uniform_bytes`
/// calls and sums the results. This is **not** RFC 9380 conformant
/// (no expand_message_xmd, no DST), but it is sound for an internal,
/// non-interoperable PRF tag: each input gives a uniformly random
/// point with no small-subgroup concerns (Ristretto is prime order).
///
/// Future interop with CFRG-VOPRF would require adding
/// `expand_message_xmd_sha512` and a DST; see RFC 9380 §5.3.
pub fn hash_to_curve(domain: &[u8], message: &[u8]) -> RistrettoPoint {
    use sha2::Digest;
    let mut h = Sha512::new();
    h.update(b"specter-sbt-h2c/");
    h.update(&(domain.len() as u64).to_be_bytes());
    h.update(domain);
    h.update(&(message.len() as u64).to_be_bytes());
    h.update(message);
    // Two-call construction via curve25519-dalek hash_from_bytes.
    RistrettoPoint::hash_from_bytes::<Sha512>(&h.finalize())
}

/// Client: blind a message into the OPRF.
///
/// Returns `(blinding_state, blinded_point)`. The blinded point is
/// sent to trustees; keep `blinding_state` private.
///
/// Never panics — both α=0 and H2C-identity are returned as typed
/// errors. α=0 is re-drawn internally (probability per-iteration
/// ~2⁻²⁵²) so the error path is only reachable on H2C identity,
/// which would indicate a broken hash-to-curve.
pub fn blind<R: CryptoRng + RngCore>(
    rng: &mut R,
    domain: &[u8],
    message: &[u8],
) -> Result<(OprfBlinding, RistrettoPoint), SbtError> {
    let base = hash_to_curve(domain, message);
    if base == RistrettoPoint::default() {
        return Err(SbtError::IdentityPoint);
    }
    // Loop until α ≠ 0. `Scalar::invert` panics on zero, and a broken
    // RNG should surface as an error, not a process crash.
    let mut alpha = Scalar::random(rng);
    while alpha == Scalar::ZERO {
        alpha = Scalar::random(rng);
    }
    let alpha_inv = alpha.invert();
    let state = OprfBlinding {
        alpha,
        alpha_inv,
        base,
    };
    let b = state.blinded();
    Ok((state, b))
}

/// Trustee: evaluate the blinded point and produce a DDH-equality
/// NIZK. The `commit` is the trustee's public share commitment.
///
/// Witness: `k_i` (`share.scalar`).
/// Statement: `Y_i = G · k_i ∧ B_i = B · k_i`.
pub fn evaluate_server<R: CryptoRng + RngCore>(
    rng: &mut R,
    share: &OprfSecretShare,
    commit: &OprfServerCommit,
    blinded: &RistrettoPoint,
    session_id: &[u8],
) -> Result<OprfEvaluation, SbtError> {
    if share.index != commit.index {
        return Err(SbtError::InvalidIndex(share.index));
    }
    // Reject 1-based indices of 0 — Shamir's secret is at x=0 so a
    // share labelled "index 0" would be the secret itself, which is
    // impossible for an honest party to possess.
    if share.index == 0 {
        return Err(SbtError::InvalidIndex(0));
    }
    if blinded == &RistrettoPoint::default() {
        return Err(SbtError::IdentityPoint);
    }
    // Sanity-check the committed share point is also non-identity.
    if commit.commit == RistrettoPoint::default() {
        return Err(SbtError::IdentityPoint);
    }
    let point = blinded * share.scalar;
    let proof = DdhEqualityProof::prove(
        rng,
        &share.scalar,
        &G,
        blinded,
        &commit.commit,
        &point,
        session_id,
        share.index,
    );
    Ok(OprfEvaluation {
        index: share.index,
        point,
        proof,
    })
}

/// Client: combine exactly `threshold` verified server evaluations
/// into `B · k` via Lagrange interpolation in the exponent.
///
/// **Hardening notes:**
/// - Requires `evaluations.len() == threshold` exactly (no silent
///   truncation).
/// - Rejects identity-point evaluations and identity commits to close
///   a small-subgroup / zero-witness attack where an attacker would
///   otherwise pass DDH-equality trivially with `(A, B) = (0, 0)`.
/// - Rejects index `0` because that is Shamir's secret coordinate.
/// - Any invalid proof causes a hard failure; the client does not
///   silently fall back to a smaller quorum.
pub fn combine_evaluations(
    threshold: usize,
    commits: &[OprfServerCommit],
    evaluations: &[OprfEvaluation],
    blinded: &RistrettoPoint,
    session_id: &[u8],
) -> Result<RistrettoPoint, SbtError> {
    if evaluations.len() != threshold {
        return Err(SbtError::Insufficient {
            got: evaluations.len(),
            need: threshold,
        });
    }
    if blinded == &RistrettoPoint::default() {
        return Err(SbtError::IdentityPoint);
    }

    // Duplicate detection and index-0 rejection.
    let mut seen = std::collections::BTreeSet::new();
    for e in evaluations {
        if e.index == 0 {
            return Err(SbtError::InvalidIndex(0));
        }
        if !seen.insert(e.index) {
            return Err(SbtError::DuplicateIndex(e.index));
        }
    }

    // Verify each trustee proof and collect indices.
    let mut picked: Vec<&OprfEvaluation> = Vec::with_capacity(threshold);
    for eval in evaluations {
        // Reject identity evaluations — they would trivially satisfy
        // DDH-equality against an identity commit and poison the
        // Lagrange sum.
        if eval.point == RistrettoPoint::default() {
            return Err(SbtError::IdentityPoint);
        }
        let commit = commits
            .iter()
            .find(|c| c.index == eval.index)
            .ok_or(SbtError::DdhEqualityFailed(eval.index))?;
        if commit.commit == RistrettoPoint::default() {
            return Err(SbtError::IdentityPoint);
        }
        eval.proof
            .verify(
                &G,
                blinded,
                &commit.commit,
                &eval.point,
                session_id,
                eval.index,
            )
            .map_err(|_| SbtError::DdhEqualityFailed(eval.index))?;
        picked.push(eval);
    }

    // Lagrange combine in the exponent.
    //    B·k = Σ λ_i · B_i
    // where λ_i = Π_{j≠i} (−j) / (i−j) mod l, evaluated at x = 0.
    let indices: Vec<u32> = picked.iter().map(|e| e.index).collect();
    let mut acc = RistrettoPoint::default();
    for eval in &picked {
        let lambda = lagrange_coefficient(eval.index, &indices)?;
        acc += eval.point * lambda;
    }
    Ok(acc)
}

/// Lagrange coefficient at x = 0 for the `i`-th point in `indices`.
///
/// Rejects `i == 0` (Shamir's secret coordinate) and any `indices`
/// entry of `0`.
pub fn lagrange_coefficient(i: u32, indices: &[u32]) -> Result<Scalar, SbtError> {
    if i == 0 {
        return Err(SbtError::InvalidIndex(0));
    }
    for &j in indices {
        if j == 0 {
            return Err(SbtError::InvalidIndex(0));
        }
    }
    let xi = Scalar::from(i as u64);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &j in indices {
        if j == i {
            continue;
        }
        let xj = Scalar::from(j as u64);
        num *= -xj;
        den *= xi - xj;
    }
    if den == Scalar::ZERO {
        return Err(SbtError::ZeroDenominator);
    }
    Ok(num * den.invert())
}

/// Client: unblind the combined point `B·k → P·k`.
pub fn unblind(state: &OprfBlinding, bk: &RistrettoPoint) -> RistrettoPoint {
    bk * state.alpha_inv
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Hand-rolled Shamir split helper for tests — uses `n=5`
    /// participants and threshold `t=3`. Mirrors what the existing
    /// specter-blind-sig::dkg module does in production.
    fn split_shamir<R: CryptoRng + RngCore>(secret: Scalar, n: u32, t: u32, rng: &mut R) -> (Vec<OprfSecretShare>, Vec<OprfServerCommit>) {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
        // Random polynomial f(x) = a_0 + a_1·x + ... + a_{t-1}·x^{t-1}
        // with a_0 = secret.
        let mut coeffs = vec![secret];
        for _ in 1..t {
            coeffs.push(Scalar::random(rng));
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
        (shares, commits)
    }

    #[test]
    fn roundtrip_single_server() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);

        let (state, b) = blind(&mut rng, b"test", b"hello world").unwrap();
        let bk = b * k; // single-server equivalent
        let pk = unblind(&state, &bk);
        // Ground truth: P·k, computed directly.
        let p = hash_to_curve(b"test", b"hello world");
        assert_eq!(pk, p * k);
    }

    #[test]
    fn threshold_3_of_5_roundtrip() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let (shares, commits) = split_shamir(k, 5, 3, &mut rng);

        let (state, b) = blind(&mut rng, b"dom", b"msg").unwrap();
        // 3 trustees evaluate.
        let mut evaluations = Vec::new();
        for i in 0..3 {
            let e = evaluate_server(
                &mut rng,
                &shares[i],
                &commits[i],
                &b,
                b"session-xyz",
            )
            .unwrap();
            evaluations.push(e);
        }

        let bk = combine_evaluations(3, &commits, &evaluations, &b, b"session-xyz").unwrap();
        let pk = unblind(&state, &bk);
        let ground = hash_to_curve(b"dom", b"msg") * k;
        assert_eq!(pk, ground);
    }

    #[test]
    fn different_three_subsets_give_same_result() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let (shares, commits) = split_shamir(k, 5, 3, &mut rng);

        let (state, b) = blind(&mut rng, b"dom", b"msg").unwrap();

        let mk_evals = |picks: &[usize]| -> Vec<OprfEvaluation> {
            picks
                .iter()
                .map(|&i| {
                    evaluate_server(&mut OsRng, &shares[i], &commits[i], &b, b"session").unwrap()
                })
                .collect()
        };

        let ev1 = mk_evals(&[0, 1, 2]);
        let ev2 = mk_evals(&[0, 2, 4]);
        let ev3 = mk_evals(&[1, 3, 4]);

        let bk1 = combine_evaluations(3, &commits, &ev1, &b, b"session").unwrap();
        let bk2 = combine_evaluations(3, &commits, &ev2, &b, b"session").unwrap();
        let bk3 = combine_evaluations(3, &commits, &ev3, &b, b"session").unwrap();

        let p1 = unblind(&state, &bk1);
        let p2 = unblind(&state, &bk2);
        let p3 = unblind(&state, &bk3);

        assert_eq!(p1, p2);
        assert_eq!(p2, p3);
    }

    #[test]
    fn tampered_share_is_rejected() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let (shares, commits) = split_shamir(k, 5, 3, &mut rng);
        let (_, b) = blind(&mut rng, b"dom", b"msg").unwrap();

        let mut evals = Vec::new();
        for i in 0..3 {
            let mut e =
                evaluate_server(&mut rng, &shares[i], &commits[i], &b, b"session").unwrap();
            if i == 1 {
                // Tamper: replace the trustee's evaluation with a
                // different random point. The DDH-equality proof
                // should fail.
                e.point = RistrettoPoint::hash_from_bytes::<Sha512>(b"tamper");
            }
            evals.push(e);
        }

        let res = combine_evaluations(3, &commits, &evals, &b, b"session");
        assert!(matches!(res, Err(SbtError::DdhEqualityFailed(_))));
    }

    #[test]
    fn insufficient_quorum_fails() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let (shares, commits) = split_shamir(k, 5, 3, &mut rng);
        let (_, b) = blind(&mut rng, b"dom", b"msg").unwrap();

        let e = evaluate_server(&mut rng, &shares[0], &commits[0], &b, b"session").unwrap();
        let res = combine_evaluations(3, &commits, &[e], &b, b"session");
        assert!(matches!(res, Err(SbtError::Insufficient { .. })));
    }

    #[test]
    fn duplicate_index_rejected() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let (shares, commits) = split_shamir(k, 5, 3, &mut rng);
        let (_, b) = blind(&mut rng, b"dom", b"msg").unwrap();

        let e0 =
            evaluate_server(&mut rng, &shares[0], &commits[0], &b, b"session").unwrap();
        let e0_dup = e0.clone();
        let e1 =
            evaluate_server(&mut rng, &shares[1], &commits[1], &b, b"session").unwrap();

        let res = combine_evaluations(
            3,
            &commits,
            &[e0, e0_dup, e1],
            &b,
            b"session",
        );
        assert!(matches!(res, Err(SbtError::DuplicateIndex(_))));
    }

    #[test]
    fn blinding_is_unlinkable() {
        // Same message, two blindings → two distinct blinded points.
        let mut rng = OsRng;
        let (_, b1) = blind(&mut rng, b"dom", b"msg").unwrap();
        let (_, b2) = blind(&mut rng, b"dom", b"msg").unwrap();
        assert_ne!(b1, b2);
    }

    #[test]
    fn unblinded_tag_is_deterministic() {
        // Same message, different blindings → same tag after unblind.
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);

        let (s1, b1) = blind(&mut rng, b"dom", b"msg").unwrap();
        let (s2, b2) = blind(&mut rng, b"dom", b"msg").unwrap();
        let t1 = unblind(&s1, &(b1 * k));
        let t2 = unblind(&s2, &(b2 * k));
        assert_eq!(t1, t2);
    }

    #[test]
    fn distinct_messages_give_distinct_tags() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let (s1, b1) = blind(&mut rng, b"dom", b"m1").unwrap();
        let (s2, b2) = blind(&mut rng, b"dom", b"m2").unwrap();
        let t1 = unblind(&s1, &(b1 * k));
        let t2 = unblind(&s2, &(b2 * k));
        assert_ne!(t1, t2);
    }

    #[test]
    fn distinct_domains_give_distinct_tags() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let (s1, b1) = blind(&mut rng, b"dom1", b"msg").unwrap();
        let (s2, b2) = blind(&mut rng, b"dom2", b"msg").unwrap();
        let t1 = unblind(&s1, &(b1 * k));
        let t2 = unblind(&s2, &(b2 * k));
        assert_ne!(t1, t2);
    }

    #[test]
    fn key_mismatch_gives_wrong_tag() {
        let mut rng = OsRng;
        let k1 = Scalar::random(&mut rng);
        let k2 = Scalar::random(&mut rng);
        let (s, b) = blind(&mut rng, b"d", b"m").unwrap();
        let t1 = unblind(&s, &(b * k1));
        let t2 = unblind(&s, &(b * k2));
        assert_ne!(t1, t2);
    }

    #[test]
    fn evaluate_rejects_identity_blinded() {
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let (shares, commits) = split_shamir(k, 3, 2, &mut rng);
        let res = evaluate_server(
            &mut rng,
            &shares[0],
            &commits[0],
            &RistrettoPoint::default(),
            b"session",
        );
        assert!(matches!(res, Err(SbtError::IdentityPoint)));
    }

    #[test]
    fn session_id_binds_evaluation() {
        // If a client reuses the same evaluation across two distinct
        // sessions the DDH proof must fail. (This is a cross-session
        // replay defence.)
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let (shares, commits) = split_shamir(k, 5, 3, &mut rng);
        let (_, b) = blind(&mut rng, b"dom", b"msg").unwrap();
        let evals: Vec<_> = (0..3)
            .map(|i| {
                evaluate_server(&mut rng, &shares[i], &commits[i], &b, b"session-A").unwrap()
            })
            .collect();

        // Combine under a different session_id.
        let res = combine_evaluations(3, &commits, &evals, &b, b"session-B");
        assert!(matches!(res, Err(SbtError::DdhEqualityFailed(_))));
    }
}
