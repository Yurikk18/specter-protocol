//! Criterion benchmarks for the SBT crypto hot paths.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use specter_primitives::pedersen::PedersenParams;
use specter_sbt::oprf::{
    blind, combine_evaluations, evaluate_server, OprfPublicKey, OprfSecretShare, OprfServerCommit,
};
use specter_sbt::proof::{DdhEqualityProof, TokenProof};
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

fn bench_oprf_blind(c: &mut Criterion) {
    c.bench_function("oprf_blind", |b| {
        b.iter(|| {
            let _ = blind(&mut OsRng, b"bench-domain", b"bench-message").unwrap();
        })
    });
}

fn bench_oprf_evaluate(c: &mut Criterion) {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (shares, commits) = split_shamir(k, 5, 3, &mut rng);
    let (_, blinded) = blind(&mut rng, b"dom", b"msg").unwrap();

    c.bench_function("oprf_evaluate_server", |b| {
        b.iter(|| {
            let _ = evaluate_server(
                &mut OsRng,
                &shares[0],
                &commits[0],
                black_box(&blinded),
                b"session-bench-16bytes",
            )
            .unwrap();
        })
    });
}

fn bench_oprf_combine(c: &mut Criterion) {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (shares, commits) = split_shamir(k, 5, 3, &mut rng);
    let (_, blinded) = blind(&mut rng, b"dom", b"msg").unwrap();
    let evals: Vec<_> = (0..3)
        .map(|i| {
            evaluate_server(
                &mut OsRng,
                &shares[i],
                &commits[i],
                &blinded,
                b"session-bench-16bytes",
            )
            .unwrap()
        })
        .collect();

    c.bench_function("oprf_combine_3of5", |b| {
        b.iter(|| {
            let _ = combine_evaluations(
                3,
                black_box(&commits),
                black_box(&evals),
                &blinded,
                b"session-bench-16bytes",
            )
            .unwrap();
        })
    });
}

fn bench_ddh_proof(c: &mut Criterion) {
    let mut rng = OsRng;
    let x = Scalar::random(&mut rng);
    let h = curve25519_dalek::ristretto::RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"h");
    let a = G * x;
    let b_pt = h * x;

    c.bench_function("ddh_equality_prove", |b| {
        b.iter(|| {
            DdhEqualityProof::prove(&mut OsRng, &x, &G, &h, &a, &b_pt, b"sess", 1);
        })
    });

    let proof = DdhEqualityProof::prove(&mut rng, &x, &G, &h, &a, &b_pt, b"sess", 1);
    c.bench_function("ddh_equality_verify", |b| {
        b.iter(|| {
            proof.verify(&G, &h, &a, &b_pt, b"sess", 1).unwrap();
        })
    });
}

fn bench_token_proof(c: &mut Criterion) {
    let mut rng = OsRng;
    let params = PedersenParams::new();
    let s = Scalar::random(&mut rng);
    let r = Scalar::random(&mut rng);
    let commit = params.g * s + params.h * r;
    let p = curve25519_dalek::ristretto::RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"p");
    let k = Scalar::random(&mut rng);
    let tag = p * k;
    let y = G * k;

    c.bench_function("token_proof_prove", |b| {
        b.iter(|| {
            TokenProof::prove(&mut OsRng, &params, &commit, &p, &tag, &s, &r, b"ctx", &y);
        })
    });

    let proof = TokenProof::prove(&mut rng, &params, &commit, &p, &tag, &s, &r, b"ctx", &y);
    c.bench_function("token_proof_verify", |b| {
        b.iter(|| {
            proof
                .verify(&params, &commit, &p, &tag, b"ctx", &y)
                .unwrap();
        })
    });
}

fn bench_end_to_end(c: &mut Criterion) {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let (shares, commits) = split_shamir(k, 5, 3, &mut rng);
    let scheme = SbtScheme::new(SbtSchemeConfig {
        pedersen: PedersenParams::new(),
        commits,
        threshold: 3,
        h2c_domain: b"bench".to_vec(),
        session_id: b"bench-session-16bytes".to_vec(),
        client_secret: [0xBB; 32],
        expected_public_key: Some(OprfPublicKey(G * k)),
        secret_key: Some(k),
    })
    .unwrap();

    c.bench_function("sbt_full_mint_cycle", |b| {
        b.iter(|| {
            let (state, req) = scheme.prepare(&mut OsRng, b"bench-payload").unwrap();
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
            scheme.verify_token(black_box(&token)).unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_oprf_blind,
    bench_oprf_evaluate,
    bench_oprf_combine,
    bench_ddh_proof,
    bench_token_proof,
    bench_end_to_end,
);
criterion_main!(benches);
