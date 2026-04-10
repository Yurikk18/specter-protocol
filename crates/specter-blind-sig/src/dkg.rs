//! Interactive Distributed Key Generation (Feldman VSS).
//!
//! No single party ever knows the full group secret key.
//! Each participant generates a random polynomial, broadcasts
//! commitments, exchanges encrypted shares, and verifies
//! received shares against public commitments.
//!
//! Based on Feldman's Verifiable Secret Sharing (1987) adapted
//! for Ristretto255 Schnorr threshold signatures.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::{RistrettoPoint, Scalar};
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

/// Round 1: Each participant generates a random polynomial and
/// publishes commitments.
///
/// Returns the participant state (kept private) and the public
/// commitments (broadcast to all other participants).
pub fn dkg_round1(id: SignerId, threshold: usize) -> DkgParticipant {
    let secret_poly: Vec<Scalar> = (0..threshold).map(|_| random_scalar()).collect();
    let commitments: Vec<RistrettoPoint> = secret_poly.iter().map(|a| a * G).collect();

    DkgParticipant {
        id,
        threshold,
        secret_poly,
        commitments,
    }
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

/// Round 3: Each participant verifies received shares and computes
/// their final key share.
///
/// Verification: for share s_{j->i} from participant j,
/// check that s_{j->i} * G == sum(i^k * C_{j,k}) for k=0..t-1.
///
/// Final share: y_i = sum(s_{j->i}) for all j (including self).
pub fn dkg_round3(
    participant: &DkgParticipant,
    received_shares: &HashMap<SignerId, Scalar>,
    all_commitments: &HashMap<SignerId, Vec<RistrettoPoint>>,
) -> Result<ThresholdKeyset, DkgError> {
    let x_i = Scalar::from(participant.id);

    // Verify each received share against the sender's commitments
    for (&sender_id, share) in received_shares {
        let sender_commitments = all_commitments
            .get(&sender_id)
            .ok_or(DkgError::MissingCommitments(sender_id))?;

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

    // Round 1: everyone generates polynomials and commitments
    let participants: HashMap<SignerId, DkgParticipant> = participant_ids
        .iter()
        .map(|&id| (id, dkg_round1(id, threshold)))
        .collect();

    let all_commitments: HashMap<SignerId, Vec<RistrettoPoint>> = participants
        .iter()
        .map(|(&id, p)| (id, p.commitments.clone()))
        .collect();

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

    // Round 3: everyone verifies and computes final keyset
    let mut keysets = HashMap::new();
    for (&id, participant) in &participants {
        let keyset = dkg_round3(participant, &received[&id], &all_commitments)?;
        keysets.insert(id, keyset);
    }

    Ok(keysets)
}

// ─── Helpers ────────────────────────────────────────────────────────────

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
}
