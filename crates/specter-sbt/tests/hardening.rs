//! Integration tests that exercise the hardening paths flagged by
//! the post-implementation security audit. Each test constructs a
//! malicious input that would succeed without the defense and asserts
//! that the library now rejects it.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use specter_primitives::pedersen::PedersenParams;
use specter_sbt::oprf::{
    blind, combine_evaluations, evaluate_server, lagrange_coefficient,
    OprfEvaluation, OprfPublicKey, OprfSecretShare, OprfServerCommit,
};
use specter_sbt::proof::{DdhEqualityProof, TokenProof};
use specter_sbt::scheme::{
    BlindSignatureScheme, SbtRequest, SbtScheme, SbtSchemeConfig, MIN_SESSION_ID_LEN,
};
use specter_sbt::SbtError;

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

fn build_scheme_3_of_5() -> (SbtScheme, Vec<OprfSecretShare>, Scalar) {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (shares, commits) = split_shamir(k, 5, 3, &mut rng);
    let scheme = SbtScheme::new(SbtSchemeConfig {
        pedersen: PedersenParams::new(),
        commits,
        threshold: 3,
        h2c_domain: b"specter-sbt-mint".to_vec(),
        session_id: b"session-id-of-at-least-16-bytes".to_vec(),
        client_secret: [0xAA; 32],
        expected_public_key: Some(OprfPublicKey(G * k)),
        secret_key: Some(k),
    })
    .unwrap();
    (scheme, shares, k)
}

#[test]
fn rejects_exactly_threshold_plus_one_evaluations() {
    let (scheme, shares, _k) = build_scheme_3_of_5();
    let (_state, req) = scheme.prepare(&mut OsRng, b"payload").unwrap();

    // 4 evaluations with threshold=3 → must fail hard, not silently
    // truncate.
    let evals: Vec<_> = (0..4)
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
    let res = combine_evaluations(3, scheme.commits(), &evals, &req.blinded, scheme.session_id());
    assert!(matches!(res, Err(SbtError::Insufficient { .. })));
}

#[test]
fn rejects_identity_blinded_point_in_combine_with_quorum_shape() {
    let (scheme, shares, _k) = build_scheme_3_of_5();
    let (_state, req) = scheme.prepare(&mut OsRng, b"payload").unwrap();

    let evals: Vec<_> = (0..3)
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

    let res = combine_evaluations(
        3,
        scheme.commits(),
        &evals,
        &RistrettoPoint::default(),
        scheme.session_id(),
    );
    assert!(matches!(res, Err(SbtError::IdentityPoint)));
}

#[test]
fn rejects_identity_evaluation_point() {
    let (scheme, shares, _k) = build_scheme_3_of_5();
    let (_state, req) = scheme.prepare(&mut OsRng, b"payload").unwrap();

    let mut evals: Vec<_> = (0..3)
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
    // Inject an identity point into the second evaluation.
    evals[1].point = RistrettoPoint::default();
    let res = combine_evaluations(3, scheme.commits(), &evals, &req.blinded, scheme.session_id());
    assert!(matches!(res, Err(SbtError::IdentityPoint)));
}

#[test]
fn rejects_index_zero_in_evaluate() {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let share = OprfSecretShare {
        index: 0, // INVALID
        scalar: k,
    };
    let commit = OprfServerCommit {
        index: 0,
        commit: G * k,
    };
    let (_s, b) = blind(&mut rng, b"dom", b"msg").unwrap();
    let res = evaluate_server(&mut rng, &share, &commit, &b, b"session-is-long-enough");
    assert!(matches!(res, Err(SbtError::InvalidIndex(0))));
}

#[test]
fn rejects_index_zero_in_lagrange() {
    let res = lagrange_coefficient(0, &[1, 2, 3]);
    assert!(matches!(res, Err(SbtError::InvalidIndex(0))));
    let res2 = lagrange_coefficient(1, &[0, 2]);
    assert!(matches!(res2, Err(SbtError::InvalidIndex(0))));
}

#[test]
fn rejects_index_zero_in_combine() {
    let (scheme, shares, _k) = build_scheme_3_of_5();
    let (_state, req) = scheme.prepare(&mut OsRng, b"payload").unwrap();

    let mut evals: Vec<_> = (0..3)
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
    // Fake an index-0 evaluation. This should be rejected before
    // any DDH verification even runs.
    evals[0].index = 0;
    let res = combine_evaluations(3, scheme.commits(), &evals, &req.blinded, scheme.session_id());
    assert!(matches!(res, Err(SbtError::InvalidIndex(0))));
}

#[test]
fn finalize_rejects_mismatched_request() {
    let (scheme, shares, _k) = build_scheme_3_of_5();
    let (state, _req) = scheme.prepare(&mut OsRng, b"payload").unwrap();

    // Craft a different request (different payload) — `state` was
    // made for `b"payload"`, not `b"other"`.
    let (_, bad_req) = scheme.prepare(&mut OsRng, b"other").unwrap();

    let evals: Vec<_> = (0..3)
        .map(|i| {
            evaluate_server(
                &mut OsRng,
                &shares[i],
                &scheme.commits()[i],
                &bad_req.blinded,
                scheme.session_id(),
            )
            .unwrap()
        })
        .collect();

    let res = scheme.finalize(&mut OsRng, state, &bad_req, &evals);
    assert!(res.is_err());
}

#[test]
fn ddh_proof_rejects_identity_inputs() {
    // Forge an all-identity proof transcript. Without the identity
    // guard, `DdhEqualityProof { t_g=0, t_h=0, z=0 }` would verify
    // against `(g=0, h=0, a=0, b=0, c)` because `0 = 0 + 0·c`.
    let proof = DdhEqualityProof {
        t_g: RistrettoPoint::default(),
        t_h: RistrettoPoint::default(),
        z: Scalar::ZERO,
    };
    let zero = RistrettoPoint::default();
    let res = proof.verify(&zero, &zero, &zero, &zero, b"sess", 1);
    assert!(res.is_err());
}

#[test]
fn token_proof_rejects_identity_tag() {
    let mut rng = OsRng;
    let params = PedersenParams::new();
    let s = Scalar::random(&mut rng);
    let r = Scalar::random(&mut rng);
    let c = params.g * s + params.h * r;
    let p = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"p");
    let k = Scalar::random(&mut rng);
    let tag = p * k;
    let y = G * k;

    let proof = TokenProof::prove(&mut rng, &params, &c, &p, &tag, &s, &r, b"ctx", &y);
    // Verify with identity tag should fail.
    let res = proof.verify(&params, &c, &p, &RistrettoPoint::default(), b"ctx", &y);
    assert!(res.is_err());
}

#[test]
fn token_proof_rejects_identity_commitment() {
    let mut rng = OsRng;
    let params = PedersenParams::new();
    let s = Scalar::random(&mut rng);
    let r = Scalar::random(&mut rng);
    let c = params.g * s + params.h * r;
    let p = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"p");
    let k = Scalar::random(&mut rng);
    let tag = p * k;
    let y = G * k;

    let proof = TokenProof::prove(&mut rng, &params, &c, &p, &tag, &s, &r, b"ctx", &y);
    let res = proof.verify(&params, &RistrettoPoint::default(), &p, &tag, b"ctx", &y);
    assert!(res.is_err());
}

#[test]
fn new_rejects_short_session_id() {
    // SbtScheme::new must refuse to construct a scheme with a short
    // session id; the old verify-time check is no longer reachable
    // because construction fails first. This is stricter.
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (_shares, commits) = split_shamir(k, 5, 3, &mut rng);
    let cfg = SbtSchemeConfig {
        pedersen: PedersenParams::new(),
        commits,
        threshold: 3,
        h2c_domain: b"d".to_vec(),
        session_id: b"short".to_vec(),
        client_secret: [0u8; 32],
        expected_public_key: Some(OprfPublicKey(G * k)),
        secret_key: None,
    };
    assert!(matches!(SbtScheme::new(cfg), Err(SbtError::SessionTooShort)));
}

#[test]
fn request_validate_accepts_wellformed() {
    let (scheme, _shares, _k) = build_scheme_3_of_5();
    let (_state, req) = scheme.prepare(&mut OsRng, b"payload").unwrap();
    req.validate().unwrap();
}

#[test]
fn request_validate_rejects_identity_points() {
    let req = SbtRequest {
        commitment: RistrettoPoint::default(),
        blinded: G,
        session_id: vec![0u8; MIN_SESSION_ID_LEN],
    };
    assert!(req.validate().is_err());

    let req2 = SbtRequest {
        commitment: G,
        blinded: RistrettoPoint::default(),
        session_id: vec![0u8; MIN_SESSION_ID_LEN],
    };
    assert!(req2.validate().is_err());
}

#[test]
fn request_validate_rejects_short_session() {
    let req = SbtRequest {
        commitment: G,
        blinded: G,
        session_id: vec![0u8; 4], // too short
    };
    assert!(req.validate().is_err());
}

#[test]
fn oprf_commit_validate_rejects_identity() {
    let c = OprfServerCommit {
        index: 1,
        commit: RistrettoPoint::default(),
    };
    assert!(c.validate().is_err());
}

#[test]
fn oprf_commit_validate_rejects_zero_index() {
    let c = OprfServerCommit {
        index: 0,
        commit: G,
    };
    assert!(c.validate().is_err());
}

#[test]
fn evaluation_validate_rejects_identity() {
    let proof = DdhEqualityProof {
        t_g: G,
        t_h: G,
        z: Scalar::ONE,
    };
    let e = OprfEvaluation {
        index: 1,
        point: RistrettoPoint::default(),
        proof,
    };
    assert!(e.validate().is_err());
}

#[test]
fn blind_never_panics_on_valid_rng() {
    // Hammer the function to ensure the α≠0 loop and H2C
    // identity-guard never fire under a healthy RNG.
    for i in 0..1024u32 {
        let msg = format!("msg-{i}");
        let _ = blind(&mut OsRng, b"dom", msg.as_bytes()).unwrap();
    }
}

#[test]
fn threshold_tag_verification_roundtrip() {
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

    // At spend time: validators re-evaluate over the UNBLINDED H2C point.
    let spend_sid = b"spend-session-id-unique";
    let spend_evals: Vec<_> = (0..3)
        .map(|i| {
            SbtScheme::evaluate_for_spend(
                &mut OsRng,
                &token,
                &shares[i],
                &scheme.commits()[i],
                scheme.h2c_domain(),
                spend_sid,
            )
            .unwrap()
        })
        .collect();

    scheme.verify_tag_threshold(&token, &spend_evals, spend_sid).unwrap();
}

#[test]
fn threshold_tag_verification_different_quorums_agree() {
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

    let sid = b"spend-session-quorum-check";
    let eval_set_a: Vec<_> = [0, 1, 2]
        .iter()
        .map(|&i| {
            SbtScheme::evaluate_for_spend(
                &mut OsRng, &token, &shares[i], &scheme.commits()[i],
                scheme.h2c_domain(), sid,
            ).unwrap()
        })
        .collect();
    let eval_set_b: Vec<_> = [0, 2, 4]
        .iter()
        .map(|&i| {
            SbtScheme::evaluate_for_spend(
                &mut OsRng, &token, &shares[i], &scheme.commits()[i],
                scheme.h2c_domain(), sid,
            ).unwrap()
        })
        .collect();

    scheme.verify_tag_threshold(&token, &eval_set_a, sid).unwrap();
    scheme.verify_tag_threshold(&token, &eval_set_b, sid).unwrap();
}

#[test]
fn threshold_tag_verification_rejects_tampered_tag() {
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
    token.tag = G * Scalar::random(&mut OsRng); // tamper

    let sid = b"spend-session-tampered";
    let evals: Vec<_> = (0..3)
        .map(|i| {
            SbtScheme::evaluate_for_spend(
                &mut OsRng, &token, &shares[i], &scheme.commits()[i],
                scheme.h2c_domain(), sid,
            ).unwrap()
        })
        .collect();

    let res = scheme.verify_tag_threshold(&token, &evals, sid);
    // Client proof will fail because the tag is tampered — it's in
    // the transcript. But the tag-origin check would also catch it.
    assert!(res.is_err());
}

#[test]
fn threshold_tag_verification_rejects_mint_session_replay() {
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

    // Try to reuse MINT-TIME evaluations as spend-time evaluations.
    // Must fail because the DDH proofs are bound to a different
    // session (mint-time session != spend-time session).
    let res = scheme.verify_tag_threshold(
        &token,
        &responses,
        b"spend-session-distinct",
    );
    assert!(res.is_err());
}

#[test]
fn threshold_tag_spend_session_must_differ_from_mint() {
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

    // Using the SAME session_id as the mint must be rejected.
    let res = scheme.verify_tag_threshold(&token, &responses, scheme.session_id());
    assert!(matches!(res, Err(SbtError::SessionMismatch)));
}

#[test]
fn pq_readiness_not_ready() {
    let r = specter_sbt::pq_readiness::PqReadiness::detect();
    assert!(!r.is_fully_pq_ready());
    assert!(r.summary().contains("NOT READY"));
}

#[test]
fn kdf_and_transcript_tags_are_independently_versioned() {
    // Regression test: any future accidental re-alignment of the
    // two crate-wide domain tags should be caught. These are
    // intentionally distinct so the KDF subsystem and the
    // Fiat-Shamir transcript subsystem can be versioned
    // independently without cross-collisions.
    use specter_sbt::scheme::SBT_KDF_TAG;
    use specter_sbt::transcript::SBT_TRANSCRIPT_TAG;
    assert_ne!(SBT_KDF_TAG, SBT_TRANSCRIPT_TAG);
    assert_eq!(SBT_KDF_TAG, b"SPECTER-SBT-KDF-v2/");
    assert_eq!(SBT_TRANSCRIPT_TAG, b"SPECTER-SBT-TRANSCRIPT-v1/");
}

#[test]
fn verify_token_refuses_without_secret_key() {
    // A production threshold scheme has no secret_key; verify_token
    // must return TagOriginCheckRequired so the caller cannot ship
    // a silent-accept verifier.
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (shares, commits) = split_shamir(k, 5, 3, &mut rng);
    let scheme = SbtScheme::new(SbtSchemeConfig {
        pedersen: PedersenParams::new(),
        commits,
        threshold: 3,
        h2c_domain: b"d".to_vec(),
        session_id: b"session-id-long-enough".to_vec(),
        client_secret: [0u8; 32],
        expected_public_key: Some(OprfPublicKey(G * k)),
        secret_key: None, // NO held key
    })
    .unwrap();
    assert!(!scheme.can_verify_tag_origin());

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

    // `verify_token` returns TagOriginCheckRequired because no key.
    let res = scheme.verify_token(&token);
    assert!(matches!(res, Err(SbtError::TagOriginCheckRequired)));

    // `verify_client_proof` succeeds.
    scheme.verify_client_proof(&token).unwrap();

    // `verify_tag_with_secret_key` with the real k succeeds.
    scheme.verify_tag_with_secret_key(&token, &k).unwrap();
}

#[test]
fn new_rejects_mismatched_secret_key() {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let k_wrong = Scalar::random(&mut rng);
    // Use 6 trustees so the disjoint-quorum cross-check runs.
    let (_shares, commits) = split_shamir(k, 6, 3, &mut rng);
    let cfg = SbtSchemeConfig {
        pedersen: PedersenParams::new(),
        commits,
        threshold: 3,
        h2c_domain: b"d".to_vec(),
        session_id: b"session-id-long-enough".to_vec(),
        client_secret: [0u8; 32],
        expected_public_key: None,
        secret_key: Some(k_wrong), // does not match commits
    };
    let res = SbtScheme::new(cfg);
    assert!(matches!(res, Err(SbtError::AggregateMismatch)));
}

#[test]
fn new_rejects_mismatched_expected_public_key() {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (_shares, commits) = split_shamir(k, 5, 3, &mut rng);
    let cfg = SbtSchemeConfig {
        pedersen: PedersenParams::new(),
        commits,
        threshold: 3,
        h2c_domain: b"d".to_vec(),
        session_id: b"session-id-long-enough".to_vec(),
        client_secret: [0u8; 32],
        expected_public_key: Some(OprfPublicKey(G * Scalar::random(&mut rng))),
        secret_key: None,
    };
    let res = SbtScheme::new(cfg);
    assert!(matches!(res, Err(SbtError::AggregateMismatch)));
}

#[test]
fn new_accepts_correct_expected_public_key() {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (_shares, commits) = split_shamir(k, 5, 3, &mut rng);
    let cfg = SbtSchemeConfig {
        pedersen: PedersenParams::new(),
        commits,
        threshold: 3,
        h2c_domain: b"d".to_vec(),
        session_id: b"session-id-long-enough".to_vec(),
        client_secret: [0u8; 32],
        expected_public_key: Some(OprfPublicKey(G * k)),
        secret_key: Some(k),
    };
    let scheme = SbtScheme::new(cfg).unwrap();
    assert!(scheme.can_verify_tag_origin());
}

#[test]
fn new_requires_expected_pk_or_disjoint_quorum() {
    // 5 trustees, threshold 3 → only 5 commits, cannot cross-check
    // two disjoint quorums of size 3 (would need 6). Must supply
    // expected_public_key or be rejected.
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (_shares, commits) = split_shamir(k, 5, 3, &mut rng);
    let cfg = SbtSchemeConfig {
        pedersen: PedersenParams::new(),
        commits,
        threshold: 3,
        h2c_domain: b"d".to_vec(),
        session_id: b"session-id-long-enough".to_vec(),
        client_secret: [0u8; 32],
        expected_public_key: None, // not supplied — must error
        secret_key: None,
    };
    let res = SbtScheme::new(cfg);
    assert!(matches!(res, Err(SbtError::AggregateMismatch)));
}

#[test]
fn new_accepts_disjoint_quorum_sized_commits() {
    // 6 trustees, threshold 3 → disjoint quorums possible, no
    // expected_public_key needed.
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (_shares, commits) = split_shamir(k, 6, 3, &mut rng);
    let cfg = SbtSchemeConfig {
        pedersen: PedersenParams::new(),
        commits,
        threshold: 3,
        h2c_domain: b"d".to_vec(),
        session_id: b"session-id-long-enough".to_vec(),
        client_secret: [0u8; 32],
        expected_public_key: None,
        secret_key: None,
    };
    SbtScheme::new(cfg).unwrap();
}

#[test]
fn tag_origin_verification_rejects_attacker_key() {
    // C-1 regression: without tag-origin check, any k' gives a
    // passing proof. With verify_tag_with_secret_key, this attack
    // must fail.
    let (scheme, shares, k_honest) = build_scheme_3_of_5();
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

    // Client-side proof is OK.
    scheme.verify_token(&token).unwrap();
    // Tag-origin check against the honest key passes.
    scheme.verify_tag_with_secret_key(&token, &k_honest).unwrap();
    // Tag-origin check against ANY other scalar must fail.
    for _ in 0..16 {
        let k_prime = Scalar::random(&mut OsRng);
        if k_prime == k_honest {
            continue;
        }
        let res = scheme.verify_tag_with_secret_key(&token, &k_prime);
        assert!(matches!(res, Err(SbtError::TagOriginMismatch)));
    }
}
