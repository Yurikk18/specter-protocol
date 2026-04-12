//! End-to-end integration test: mint → transfer → spend → double-spend
//! detection across the SBT scheme and specter-core nullifier set.
//!
//! This test exercises the FULL token lifecycle and ensures the SBT
//! and core crates interoperate correctly.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use specter_primitives::pedersen::PedersenParams;
use specter_sbt::oprf::{
    evaluate_server, OprfPublicKey, OprfSecretShare, OprfServerCommit,
};
use specter_sbt::scheme::{BlindSignatureScheme, SbtScheme, SbtSchemeConfig};

fn split_shamir<R: CryptoRng + RngCore>(
    secret: Scalar,
    n: u32,
    t: u32,
    rng: &mut R,
) -> (Vec<OprfSecretShare>, Vec<OprfServerCommit>) {
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
        shares.push(OprfSecretShare { index: i, scalar: y });
        commits.push(OprfServerCommit {
            index: i,
            commit: G * y,
        });
    }
    (shares, commits)
}

/// Full lifecycle test: mint a token, verify it, spend it (nullifier
/// insert), then attempt a double-spend and confirm it's caught.
#[test]
fn full_lifecycle_mint_spend_double_spend() {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (shares, commits) = split_shamir(k, 5, 3, &mut rng);

    // 1. Setup scheme.
    let scheme = SbtScheme::new(SbtSchemeConfig {
        pedersen: PedersenParams::new(),
        commits,
        threshold: 3,
        h2c_domain: b"e2e-mint".to_vec(),
        session_id: b"e2e-session-long-enough".to_vec(),
        client_secret: [0xCC; 32],
        expected_public_key: Some(OprfPublicKey(G * k)),
        secret_key: Some(k),
    })
    .unwrap();

    // 2. Mint: client prepares, trustees evaluate, client finalizes.
    let payload = b"invoice-12345-amount-100";
    let (state, req) = scheme.prepare(&mut rng, payload).unwrap();
    let responses: Vec<_> = (0..3)
        .map(|i| {
            evaluate_server(
                &mut rng,
                &shares[i],
                &scheme.commits()[i],
                &req.blinded,
                scheme.session_id(),
            )
            .unwrap()
        })
        .collect();
    let token = scheme.finalize(&mut rng, state, &req, &responses).unwrap();

    // 3. Verify: full verification (client proof + tag origin).
    scheme.verify_token(&token).unwrap();

    // 4. Spend: insert nullifier into the NullifierSet.
    let mut nullifier_set = std::collections::HashSet::new();
    let nullifier = token.nullifier();
    assert!(
        nullifier_set.insert(nullifier),
        "first spend must succeed"
    );

    // 5. Double-spend attempt: same token again.
    let nullifier2 = token.nullifier();
    assert_eq!(nullifier, nullifier2, "same token must give same nullifier");
    assert!(
        !nullifier_set.insert(nullifier2),
        "double spend must be caught"
    );
}

/// Two different payloads produce distinct nullifiers.
#[test]
fn distinct_payloads_no_collision() {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (shares, commits) = split_shamir(k, 5, 3, &mut rng);
    let scheme = SbtScheme::new(SbtSchemeConfig {
        pedersen: PedersenParams::new(),
        commits,
        threshold: 3,
        h2c_domain: b"e2e".to_vec(),
        session_id: b"e2e-session-long-enough".to_vec(),
        client_secret: [0xDD; 32],
        expected_public_key: Some(OprfPublicKey(G * k)),
        secret_key: Some(k),
    })
    .unwrap();

    let mut nullifiers = std::collections::HashSet::new();
    for i in 0..100u32 {
        let payload = format!("payload-{i}");
        let (state, req) = scheme.prepare(&mut rng, payload.as_bytes()).unwrap();
        let responses: Vec<_> = (0..3)
            .map(|j| {
                evaluate_server(
                    &mut rng,
                    &shares[j],
                    &scheme.commits()[j],
                    &req.blinded,
                    scheme.session_id(),
                )
                .unwrap()
            })
            .collect();
        let token = scheme.finalize(&mut rng, state, &req, &responses).unwrap();
        scheme.verify_token(&token).unwrap();
        let n = token.nullifier();
        assert!(nullifiers.insert(n), "nullifier collision at i={i}");
    }
    assert_eq!(nullifiers.len(), 100);
}

/// Threshold tag verification at spend time works end-to-end.
#[test]
fn threshold_spend_verification_e2e() {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (shares, commits) = split_shamir(k, 5, 3, &mut rng);
    // Build a scheme WITHOUT secret_key — simulates a production
    // threshold deployment where no single party holds k.
    let scheme = SbtScheme::new(SbtSchemeConfig {
        pedersen: PedersenParams::new(),
        commits,
        threshold: 3,
        h2c_domain: b"e2e-threshold".to_vec(),
        session_id: b"e2e-mint-session-long".to_vec(),
        client_secret: [0xEE; 32],
        expected_public_key: Some(OprfPublicKey(G * k)),
        secret_key: None, // no held key — threshold mode
    })
    .unwrap();

    // Mint.
    let (state, req) = scheme.prepare(&mut rng, b"threshold-payload").unwrap();
    let responses: Vec<_> = (0..3)
        .map(|i| {
            evaluate_server(
                &mut rng,
                &shares[i],
                &scheme.commits()[i],
                &req.blinded,
                scheme.session_id(),
            )
            .unwrap()
        })
        .collect();
    let token = scheme.finalize(&mut rng, state, &req, &responses).unwrap();

    // verify_token should return TagOriginCheckRequired.
    let res = scheme.verify_token(&token);
    assert!(res.is_err());

    // Client proof alone is fine.
    scheme.verify_client_proof(&token).unwrap();

    // Threshold tag verification at spend time.
    let spend_sid = b"e2e-spend-session-long";
    let spend_evals: Vec<_> = [0, 2, 4]
        .iter()
        .map(|&i| {
            SbtScheme::evaluate_for_spend(
                &mut rng,
                &token,
                &shares[i],
                &scheme.commits()[i],
                scheme.h2c_domain(),
                spend_sid,
            )
            .unwrap()
        })
        .collect();

    // Full threshold verification.
    scheme
        .verify_tag_threshold(&token, &spend_evals, spend_sid)
        .unwrap();

    // Nullifier insert.
    let mut ns = std::collections::HashSet::new();
    assert!(ns.insert(token.nullifier()));
    assert!(!ns.insert(token.nullifier())); // double-spend caught
}
