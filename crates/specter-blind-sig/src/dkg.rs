//! Interactive Distributed Key Generation (Feldman VSS).
//!
//! No single party ever knows the full group secret key.
//! Each participant generates a random polynomial, broadcasts
//! commitments, exchanges encrypted shares, and verifies
//! received shares against public commitments.
//!
//! Based on Feldman's Verifiable Secret Sharing (1987) adapted
//! for Ristretto255 Schnorr threshold signatures.
//!
//! Each participant provides a Schnorr proof-of-knowledge of
//! their secret polynomial's constant term in Round 1 to prevent
//! rogue-key attacks.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};
use std::collections::HashMap;

use specter_primitives::scalar_utils::random_scalar;
use specter_primitives::shamir::Share;

use crate::threshold::{SignerId, ThresholdKeyset};

/// A DKG participant's state during the protocol.
pub struct DkgParticipant {
    pub id: SignerId,
    threshold: usize,
    /// Secret polynomial coefficients (a_0, a_1, ..., a_{t-1}).
    secret_poly: Vec<Scalar>,
    /// Public commitments: C_j = a_j * G for each coefficient.
    pub commitments: Vec<RistrettoPoint>,
}

impl Drop for DkgParticipant {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for s in &mut self.secret_poly {
            s.zeroize();
        }
    }
}

/// Schnorr proof-of-knowledge of a discrete logarithm.
///
/// Proves knowledge of the scalar `a_0` such that `C_0 = a_0 * G`
/// without revealing `a_0`. Used in DKG Round 1 to prevent
/// rogue-key attacks where a malicious participant sets their
/// commitment to control the group public key.
pub struct ProofOfKnowledge {
    /// The commitment R = k * G for the random nonce k.
    pub r: RistrettoPoint,
    /// The response s = k + e * a_0 where e is the challenge hash.
    pub s: Scalar,
}

impl Drop for ProofOfKnowledge {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.s.zeroize();
    }
}

/// Round 1: Each participant generates a random polynomial and
/// publishes commitments along with a Schnorr proof-of-knowledge.
///
/// Returns the participant state (kept private), the public
/// commitments, and a proof-of-knowledge of the constant term
/// (all broadcast to all other participants).
pub fn dkg_round1(id: SignerId, threshold: usize) -> (DkgParticipant, ProofOfKnowledge) {
    let secret_poly: Vec<Scalar> = (0..threshold).map(|_| random_scalar()).collect();
    let commitments: Vec<RistrettoPoint> = secret_poly.iter().map(|a| a * G).collect();

    // Schnorr PoK of secret_poly[0]: proves knowledge of discrete log of commitments[0]
    let k = random_scalar();
    let pok_r = k * G;
    let pok_e = hash_dkg_pok(id, &commitments[0], &pok_r);
    let pok_s = k + pok_e * secret_poly[0];

    let pok = ProofOfKnowledge { r: pok_r, s: pok_s };

    let participant = DkgParticipant {
        id,
        threshold,
        secret_poly,
        commitments,
    };

    (participant, pok)
}

/// Verify a Schnorr proof-of-knowledge for a participant's constant-term commitment.
///
/// Checks that the prover knows the discrete log of `commitment_0`
/// (i.e., the scalar `a_0` such that `commitment_0 = a_0 * G`).
///
/// Verification: `s * G == R + e * C_0` where `e = H(id || C_0 || R)`.
pub fn verify_pok(
    id: SignerId,
    commitment_0: &RistrettoPoint,
    pok: &ProofOfKnowledge,
) -> bool {
    let e = hash_dkg_pok(id, commitment_0, &pok.r);
    let lhs = pok.s * G;
    let rhs = pok.r + e * commitment_0;
    lhs == rhs
}

/// Round 2: Each participant computes shares for every other participant.
///
/// For participant j, the share is: s_{i->j} = f_i(j)
/// where f_i is participant i's secret polynomial.
pub fn dkg_round2(
    participant: &DkgParticipant,
    all_ids: &[SignerId],
) -> HashMap<SignerId, Scalar> {
    let mut shares = HashMap::new();
    for &target_id in all_ids {
        if target_id == participant.id {
            continue;
        }
        let x = Scalar::from(target_id);
        let share = evaluate_poly(&participant.secret_poly, &x);
        shares.insert(target_id, share);
    }
    shares
}

/// Round 3: Each participant verifies received proofs-of-knowledge
/// and shares, then computes their final key share.
///
/// PoK verification: for each participant j, verify their Schnorr
/// proof-of-knowledge of the constant term a_{j,0}.
///
/// Share verification: for share s_{j->i} from participant j,
/// check that s_{j->i} * G == sum(i^k * C_{j,k}) for k=0..t-1.
///
/// Final share: y_i = sum(s_{j->i}) for all j (including self).
pub fn dkg_round3(
    participant: &DkgParticipant,
    received_shares: &HashMap<SignerId, Scalar>,
    all_commitments: &HashMap<SignerId, Vec<RistrettoPoint>>,
    all_poks: &HashMap<SignerId, ProofOfKnowledge>,
) -> Result<ThresholdKeyset, DkgError> {
    let x_i = Scalar::from(participant.id);

    // Verify all proofs-of-knowledge before processing shares
    for (&pid, commitments) in all_commitments {
        let pok = all_poks
            .get(&pid)
            .ok_or(DkgError::MissingProofOfKnowledge(pid))?;
        if !verify_pok(pid, &commitments[0], pok) {
            return Err(DkgError::InvalidProofOfKnowledge(pid));
        }
    }

    // Verify each received share against the sender's commitments
    for (&sender_id, share) in received_shares {
        let sender_commitments = all_commitments
            .get(&sender_id)
            .ok_or(DkgError::MissingCommitments(sender_id))?;

        // Reject commitment vectors that don't match the threshold.
        // A longer vector encodes a higher-degree polynomial,
        // silently raising the effective threshold (threshold-raising attack,
        // Trail of Bits 2024).
        if sender_commitments.len() != participant.threshold {
            return Err(DkgError::InvalidCommitmentLength {
                from: sender_id,
                expected: participant.threshold,
                got: sender_commitments.len(),
            });
        }

        // Expected: share * G == sum(x_i^k * C_{sender,k})
        let expected = evaluate_poly_points(sender_commitments, &x_i);
        let actual = share * G;

        if actual != expected {
            return Err(DkgError::InvalidShare {
                from: sender_id,
                to: participant.id,
            });
        }
    }

    // Compute own share of own polynomial: f_i(i)
    let self_share = evaluate_poly(&participant.secret_poly, &x_i);

    // Final key share: y_i = self_share + sum(received_shares)
    let total_share = received_shares.values().fold(self_share, |acc, s| acc + s);

    // Group public key: sum of all C_{j,0} (constant terms of each polynomial)
    let group_public: RistrettoPoint = all_commitments
        .values()
        .map(|commits| commits[0])
        .fold(RistrettoPoint::default(), |acc, c| acc + c);

    // Build the keyset
    let all_ids: Vec<SignerId> = all_commitments.keys().copied().collect();
    let mut shares = HashMap::new();
    let mut public_shares = HashMap::new();

    // This participant's share
    let share = Share {
        x: x_i,
        y: total_share,
    };
    public_shares.insert(participant.id, total_share * G);
    shares.insert(participant.id, share);

    // Compute public shares for other participants from commitments
    for &other_id in &all_ids {
        if other_id == participant.id {
            continue;
        }
        let x_j = Scalar::from(other_id);
        let pk_j: RistrettoPoint = all_commitments
            .values()
            .map(|commits| evaluate_poly_points(commits, &x_j))
            .fold(RistrettoPoint::default(), |acc, p| acc + p);
        public_shares.insert(other_id, pk_j);
    }

    Ok(ThresholdKeyset {
        group_public,
        threshold: participant.threshold,
        total: all_ids.len(),
        shares,
        public_shares,
    })
}

/// Proactive resharing of an existing threshold keyset.
///
/// Re-randomizes every participant's Shamir share without changing the
/// group public key. After a successful reshare, any attacker who had
/// compromised some (but fewer than `t`) old shares must start over
/// from scratch — old shares are useless once the new polynomial is in
/// place.
///
/// # Protocol
///
/// Based on Herzberg et al., "Proactive Secret Sharing Or: How to Cope
/// With Perpetual Leakage" (CRYPTO 1995). Each participant `i`:
///
/// 1. Generates a random polynomial `g_i(x)` of degree `t-1` with
///    `g_i(0) == 0` (so adding it to the current group polynomial
///    `f(x)` preserves the constant term, i.e., the group secret).
/// 2. Distributes `g_i(j)` to every other participant `j`.
/// 3. Every participant `j` updates their share:
///    `y'_j = y_j + sum_i g_i(j)`.
///
/// In a real deployment this requires an interactive multi-round
/// protocol with verification (Feldman VSS) of each contribution.
/// This function runs the whole thing locally as a simulation — it
/// takes ownership of the current keyset and returns the re-randomized
/// keyset. A production interactive version would live behind a
/// network protocol on top of this helper.
///
/// # Guarantees
///
/// - `group_public` is unchanged (verified at the end of the function).
/// - Every returned share verifies against the same group public key
///   as the input keyset.
/// - Old shares inside the input keyset are zeroized on drop (the
///   caller's copy of `old` is consumed by this call).
///
/// # Errors
///
/// Returns [`DkgError::InvalidShareReshare`] if the resulting group
/// public key does not match the input — an internal consistency
/// check that should never fire under honest participants but is kept
/// as a defensive guard against future bug introductions.
pub fn proactive_reshare(
    old: ThresholdKeyset,
) -> Result<ThresholdKeyset, DkgError> {
    let t = old.threshold;
    let ids: Vec<SignerId> = old.shares.keys().copied().collect();

    // Step 1: each participant i generates a random polynomial
    // g_i(x) of degree t-1 with g_i(0) = 0. We store the coefficients
    // a_1..a_{t-1}; the constant term a_0 is implicitly 0.
    let mut update_polys: HashMap<SignerId, Vec<Scalar>> = HashMap::new();
    for &i in &ids {
        // t-1 random coefficients (skipping a_0 = 0).
        let coeffs: Vec<Scalar> = (0..t.saturating_sub(1)).map(|_| random_scalar()).collect();
        update_polys.insert(i, coeffs);
    }

    // Step 2: compute updated shares y'_j = y_j + sum_i g_i(j).
    //
    // g_i(j) = a_{i,1} * j + a_{i,2} * j^2 + ... + a_{i,t-1} * j^{t-1}
    // (no constant term).
    let mut new_shares: HashMap<SignerId, Share> = HashMap::new();
    for &j in &ids {
        let xj = Scalar::from(j);
        // Start with the current share for participant j.
        let current_y = old.shares[&j].y;
        let mut new_y = current_y;

        for (&_i, coeffs) in &update_polys {
            // Evaluate g_i at xj, with implicit constant term 0.
            let mut x_power = xj;
            for coeff in coeffs {
                new_y += coeff * x_power;
                x_power *= xj;
            }
        }

        new_shares.insert(
            j,
            Share {
                x: xj,
                y: new_y,
            },
        );
    }

    // Step 3: derive the new public shares and the group public key.
    // The group public key should be identical to the input; we
    // reconstruct it from the new shares and verify.
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as BP_G;
    let mut new_public_shares: HashMap<SignerId, RistrettoPoint> = HashMap::new();
    for (&id, share) in &new_shares {
        new_public_shares.insert(id, share.y * BP_G);
    }

    // Reconstruct the group public key via Lagrange interpolation at
    // x = 0. If the proactive reshare preserved the constant term,
    // this equals `old.group_public`.
    //
    // We use any `t` points — pick the first t participants.
    let subset: Vec<SignerId> = ids.iter().copied().take(t).collect();
    let reconstructed = {
        let mut acc = RistrettoPoint::default();
        for &i in &subset {
            let xi = Scalar::from(i);
            let pk_i = new_public_shares[&i];
            // Lagrange basis at 0: L_i(0) = product_{j != i} (-x_j) / (x_i - x_j)
            let mut lambda = Scalar::ONE;
            for &j in &subset {
                if i == j {
                    continue;
                }
                let xj = Scalar::from(j);
                lambda *= (-xj) * (xi - xj).invert();
            }
            acc += lambda * pk_i;
        }
        acc
    };

    if reconstructed != old.group_public {
        return Err(DkgError::InvalidShareReshare);
    }

    Ok(ThresholdKeyset {
        group_public: old.group_public,
        threshold: t,
        total: old.total,
        shares: new_shares,
        public_shares: new_public_shares,
    })
    // `old` is consumed by the function call; its Drop impl
    // zeroizes every y-coordinate of the old shares.
}

/// Run a complete DKG among all participants (convenience function).
///
/// Simulates the 3-round protocol and returns a keyset for each participant.
pub fn run_dkg(
    threshold: usize,
    participant_ids: &[SignerId],
) -> Result<HashMap<SignerId, ThresholdKeyset>, DkgError> {
    let total = participant_ids.len();
    if threshold > total || threshold == 0 || total == 0 {
        return Err(DkgError::InvalidParams { threshold, total });
    }

    // Round 1: everyone generates polynomials, commitments, and PoKs
    let mut participants: HashMap<SignerId, DkgParticipant> = HashMap::new();
    let mut all_poks: HashMap<SignerId, ProofOfKnowledge> = HashMap::new();
    for &id in participant_ids {
        let (participant, pok) = dkg_round1(id, threshold);
        participants.insert(id, participant);
        all_poks.insert(id, pok);
    }

    let all_commitments: HashMap<SignerId, Vec<RistrettoPoint>> = participants
        .iter()
        .map(|(&id, p)| (id, p.commitments.clone()))
        .collect();

    // Validate commitment vector lengths before Round 2 (threshold-raising defense)
    for (&id, commits) in &all_commitments {
        if commits.len() != threshold {
            return Err(DkgError::InvalidCommitmentLength {
                from: id,
                expected: threshold,
                got: commits.len(),
            });
        }
    }

    // Verify all PoKs before proceeding to Round 2
    for (&pid, commitments) in &all_commitments {
        let pok = all_poks
            .get(&pid)
            .ok_or(DkgError::MissingProofOfKnowledge(pid))?;
        if !verify_pok(pid, &commitments[0], pok) {
            return Err(DkgError::InvalidProofOfKnowledge(pid));
        }
    }

    // Round 2: everyone computes shares for everyone else
    let all_shares: HashMap<SignerId, HashMap<SignerId, Scalar>> = participants
        .iter()
        .map(|(&id, p)| (id, dkg_round2(p, participant_ids)))
        .collect();

    // Reorganize: for each participant, collect shares FROM others
    let mut received: HashMap<SignerId, HashMap<SignerId, Scalar>> = HashMap::new();
    for &target_id in participant_ids {
        let mut shares_for_target = HashMap::new();
        for &sender_id in participant_ids {
            if sender_id == target_id {
                continue;
            }
            let share = all_shares[&sender_id][&target_id];
            shares_for_target.insert(sender_id, share);
        }
        received.insert(target_id, shares_for_target);
    }

    // Round 3: everyone verifies PoKs again, verifies shares, and computes final keyset
    let mut keysets = HashMap::new();
    for (&id, participant) in &participants {
        let keyset = dkg_round3(participant, &received[&id], &all_commitments, &all_poks)?;
        keysets.insert(id, keyset);
    }

    Ok(keysets)
}

// ─── Helpers ────────────────────────────────────────────────────────────

/// Hash function for the DKG proof-of-knowledge challenge.
///
/// Computes `e = H(domain || id || C_0 || R)` using SHA-512 with
/// domain separation to produce a scalar challenge.
fn hash_dkg_pok(id: SignerId, commitment: &RistrettoPoint, r: &RistrettoPoint) -> Scalar {
    let hash = Sha512::new()
        .chain_update(b"specter-dkg-pok:")
        .chain_update(id.to_le_bytes())
        .chain_update(commitment.compress().as_bytes())
        .chain_update(r.compress().as_bytes())
        .finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn evaluate_poly(coeffs: &[Scalar], x: &Scalar) -> Scalar {
    let mut result = Scalar::ZERO;
    let mut x_power = Scalar::ONE;
    for coeff in coeffs {
        result += coeff * x_power;
        x_power *= x;
    }
    result
}

fn evaluate_poly_points(points: &[RistrettoPoint], x: &Scalar) -> RistrettoPoint {
    let mut result = RistrettoPoint::default();
    let mut x_power = Scalar::ONE;
    for point in points {
        result += x_power * point;
        x_power *= x;
    }
    result
}

/// DKG errors.
#[derive(Debug, thiserror::Error)]
pub enum DkgError {
    #[error("missing commitments from participant {0}")]
    MissingCommitments(SignerId),

    #[error("invalid share from participant {from} to participant {to}")]
    InvalidShare { from: SignerId, to: SignerId },

    #[error("invalid DKG parameters: threshold={threshold}, total={total}")]
    InvalidParams { threshold: usize, total: usize },

    #[error("missing proof-of-knowledge from participant {0}")]
    MissingProofOfKnowledge(SignerId),

    #[error("invalid proof-of-knowledge from participant {0}")]
    InvalidProofOfKnowledge(SignerId),

    #[error("invalid commitment vector length from participant {from}: expected {expected}, got {got}")]
    InvalidCommitmentLength { from: SignerId, expected: usize, got: usize },

    #[error("proactive reshare produced a different group public key — internal consistency failure")]
    InvalidShareReshare,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schnorr_blind;
    use crate::threshold;

    #[test]
    fn test_dkg_2_of_3() {
        let keysets = run_dkg(2, &[1, 2, 3]).unwrap();

        // All participants must agree on the same group public key
        let pk1 = keysets[&1].group_public;
        let pk2 = keysets[&2].group_public;
        let pk3 = keysets[&3].group_public;
        assert_eq!(pk1, pk2);
        assert_eq!(pk2, pk3);
    }

    #[test]
    fn test_dkg_3_of_5() {
        let keysets = run_dkg(3, &[1, 2, 3, 4, 5]).unwrap();

        let pks: Vec<RistrettoPoint> = keysets.values().map(|k| k.group_public).collect();
        assert!(pks.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn test_dkg_keys_work_with_threshold_signing() {
        let keysets = run_dkg(2, &[1, 2, 3]).unwrap();

        // Merge all shares into a combined keyset for threshold signing
        // (in production, signing is distributed - each signer uses their own share)
        let mut combined = keysets[&1].clone();
        for (&id, ks) in &keysets {
            if let Some(share) = ks.shares.get(&id) {
                combined.shares.insert(id, share.clone());
            }
        }

        let message = b"DKG-signed token";
        let sig = threshold::threshold_blind_sign(&combined, &[1, 2], message).unwrap();
        assert!(schnorr_blind::verify(&combined.group_public, message, &sig));
    }

    #[test]
    fn test_dkg_different_subsets_work() {
        let keysets = run_dkg(2, &[1, 2, 3]).unwrap();

        let mut combined = keysets[&1].clone();
        for (&id, ks) in &keysets {
            if let Some(share) = ks.shares.get(&id) {
                combined.shares.insert(id, share.clone());
            }
        }
        let msg = b"test";

        let s1 = threshold::threshold_blind_sign(&combined, &[1, 2], msg).unwrap();
        let s2 = threshold::threshold_blind_sign(&combined, &[2, 3], msg).unwrap();
        let s3 = threshold::threshold_blind_sign(&combined, &[1, 3], msg).unwrap();

        assert!(schnorr_blind::verify(&combined.group_public, msg, &s1));
        assert!(schnorr_blind::verify(&combined.group_public, msg, &s2));
        assert!(schnorr_blind::verify(&combined.group_public, msg, &s3));
    }

    #[test]
    fn test_dkg_no_single_party_knows_secret() {
        let keysets = run_dkg(2, &[1, 2, 3]).unwrap();

        // Each participant only has their own share, not the full secret
        // The group public key is the same for all, but no one has the secret
        let share1 = &keysets[&1].shares[&1].y;
        let share2 = &keysets[&2].shares[&2].y;

        // Shares are different (each participant has a unique share)
        assert_ne!(share1, share2);
    }

    #[test]
    fn test_dkg_invalid_params() {
        assert!(run_dkg(0, &[1, 2, 3]).is_err());
        assert!(run_dkg(5, &[1, 2, 3]).is_err());
    }

    #[test]
    fn test_pok_valid_proof_verifies() {
        // Generate a participant with a PoK and verify it passes
        let (participant, pok) = dkg_round1(1, 2);
        assert!(
            verify_pok(participant.id, &participant.commitments[0], &pok),
            "valid PoK should verify"
        );
    }

    #[test]
    fn test_pok_multiple_participants_all_verify() {
        for id in 1..=5 {
            let (participant, pok) = dkg_round1(id, 3);
            assert!(
                verify_pok(participant.id, &participant.commitments[0], &pok),
                "valid PoK for participant {} should verify",
                id
            );
        }
    }

    #[test]
    fn test_pok_forged_wrong_scalar_rejected() {
        // A forged proof with a random s value should fail verification
        let (participant, _pok) = dkg_round1(1, 2);
        let forged = ProofOfKnowledge {
            r: random_scalar() * G,
            s: random_scalar(),
        };
        assert!(
            !verify_pok(participant.id, &participant.commitments[0], &forged),
            "forged PoK with random s should be rejected"
        );
    }

    #[test]
    fn test_pok_forged_wrong_id_rejected() {
        // A proof generated for participant 1 should not verify for participant 2
        let (participant, pok) = dkg_round1(1, 2);
        let wrong_id: SignerId = 2;
        assert!(
            !verify_pok(wrong_id, &participant.commitments[0], &pok),
            "PoK verified with wrong participant ID should be rejected"
        );
    }

    #[test]
    fn test_pok_forged_wrong_commitment_rejected() {
        // A proof generated for one commitment should not verify against a different commitment
        let (participant_a, pok_a) = dkg_round1(1, 2);
        let (participant_b, _pok_b) = dkg_round1(1, 2);
        // Use participant A's PoK against participant B's commitment
        assert!(
            !verify_pok(1, &participant_b.commitments[0], &pok_a),
            "PoK verified against wrong commitment should be rejected"
        );
        // Also verify the PoK still works against the correct commitment
        assert!(verify_pok(1, &participant_a.commitments[0], &pok_a));
    }

    // ── Proactive resharing tests ─────────────────────────────────────

    #[test]
    fn test_proactive_reshare_preserves_group_pk() {
        use crate::threshold;
        let keyset = threshold::dealer_keygen(2, 3);
        let original_pk = keyset.group_public;
        let original_shares: Vec<(SignerId, Scalar)> = keyset
            .shares
            .iter()
            .map(|(id, s)| (*id, s.y))
            .collect();

        let reshared = proactive_reshare(keyset).unwrap();
        assert_eq!(reshared.group_public, original_pk);

        // The individual shares must have changed — this is the core
        // guarantee of proactive resharing. An attacker who leaked
        // shares before the reshare cannot combine them with new
        // shares.
        for (id, old_y) in original_shares {
            let new_y = reshared.shares[&id].y;
            assert_ne!(new_y, old_y, "share {} was not re-randomized", id);
        }
    }

    #[test]
    fn test_proactive_reshare_new_shares_still_sign() {
        use crate::{schnorr_blind, threshold};
        let keyset = threshold::dealer_keygen(2, 3);
        let reshared = proactive_reshare(keyset).unwrap();

        // The re-randomized keyset must still produce valid threshold
        // signatures.
        let msg = b"post-reshare message";
        let sig = threshold::threshold_blind_sign(&reshared, &[1, 2], msg).unwrap();
        assert!(schnorr_blind::verify(&reshared.group_public, msg, &sig));
    }

    #[test]
    fn test_proactive_reshare_chained() {
        use crate::{schnorr_blind, threshold};
        // Run three reshare rounds back to back. Every round must
        // preserve the group pk AND produce fresh shares.
        let mut keyset = threshold::dealer_keygen(2, 3);
        let initial_pk = keyset.group_public;
        for round in 0..3 {
            let reshared = proactive_reshare(keyset).unwrap();
            assert_eq!(reshared.group_public, initial_pk);
            // After each round, a threshold sig still works.
            let msg = format!("round-{}", round);
            let sig =
                threshold::threshold_blind_sign(&reshared, &[1, 2], msg.as_bytes()).unwrap();
            assert!(schnorr_blind::verify(
                &reshared.group_public,
                msg.as_bytes(),
                &sig
            ));
            keyset = reshared;
        }
    }

    #[test]
    fn test_dkg_with_pok_round3_rejects_invalid_pok() {
        // Manually run the protocol and inject a forged PoK
        let ids: Vec<SignerId> = vec![1, 2, 3];
        let threshold = 2;

        let mut participants = HashMap::new();
        let mut all_poks = HashMap::new();
        for &id in &ids {
            let (p, pok) = dkg_round1(id, threshold);
            participants.insert(id, p);
            all_poks.insert(id, pok);
        }

        let all_commitments: HashMap<SignerId, Vec<RistrettoPoint>> = participants
            .iter()
            .map(|(&id, p)| (id, p.commitments.clone()))
            .collect();

        // Forge participant 2's PoK
        all_poks.insert(
            2,
            ProofOfKnowledge {
                r: random_scalar() * G,
                s: random_scalar(),
            },
        );

        // Round 2
        let all_shares: HashMap<SignerId, HashMap<SignerId, Scalar>> = participants
            .iter()
            .map(|(&id, p)| (id, dkg_round2(p, &ids)))
            .collect();

        let mut received: HashMap<SignerId, HashMap<SignerId, Scalar>> = HashMap::new();
        for &target_id in &ids {
            let mut shares_for_target = HashMap::new();
            for &sender_id in &ids {
                if sender_id == target_id {
                    continue;
                }
                shares_for_target.insert(sender_id, all_shares[&sender_id][&target_id]);
            }
            received.insert(target_id, shares_for_target);
        }

        // Round 3 should reject the forged PoK
        let result = dkg_round3(
            &participants[&1],
            &received[&1],
            &all_commitments,
            &all_poks,
        );
        assert!(result.is_err(), "dkg_round3 should reject forged PoK");
        match result {
            Err(DkgError::InvalidProofOfKnowledge(id)) => assert_eq!(id, 2),
            Err(other) => panic!("expected InvalidProofOfKnowledge(2), got {:?}", other),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}
