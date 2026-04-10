//! End-to-end integration tests for the Specter protocol.

use specter_credential::credential::Attributes;
use specter_core::mint::{Mint, MintConfig};
use specter_core::nullifier::NullifierSet;
use specter_core::transfer;
use specter_core::verify;

fn setup_mint(threshold: usize, total: usize, bound: u32) -> Mint {
    Mint::setup(MintConfig {
        threshold,
        total_signers: total,
        recursion_bound: bound,
    })
}

fn test_attrs() -> Attributes {
    Attributes {
        kyc_passed: true,
        not_sanctioned: true,
        jurisdiction: "EU".to_string(),
        age_over_18: true,
            expires_at: 0,
    }
}

#[test]
fn test_full_lifecycle_with_credentials() {
    let mint = setup_mint(2, 3, 20);
    let token = mint.issue(1000, &[1, 2], Some(&test_attrs())).unwrap();

    let vr = verify::verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0);
    assert!(vr.all_valid());
    assert_eq!(vr.credential_valid, Some(true));

    let mut current = token;
    let mut nullifier_set = NullifierSet::new();
    for i in 0..10 {
        let result = transfer::transfer(current, &mut nullifier_set).unwrap();
        let vr = verify::verify_token(&result.token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0);
        assert!(vr.all_valid(), "failed at step {}", i);
        current = result.token;
    }
    assert_eq!(current.transfer_count, 10);
}

#[test]
fn test_full_lifecycle_without_credentials() {
    let mint = setup_mint(2, 3, 20);
    let token = mint.issue(1000, &[1, 2], None).unwrap();
    let vr = verify::verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0);
    assert!(vr.all_valid());

    let mut ns = NullifierSet::new();
    let mut current = token;
    for _ in 0..10 {
        current = transfer::transfer(current, &mut ns).unwrap().token;
    }
    let vr = verify::verify_token(&current, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0);
    assert!(vr.all_valid());
}

#[test]
fn test_double_spend_detection() {
    let mint = setup_mint(2, 3, 20);
    let token = mint.issue(1000, &[1, 2], None).unwrap();
    let mut ns = NullifierSet::new();
    let _s1 = transfer::transfer(token.clone(), &mut ns).unwrap();
    // Second transfer of the same token should fail with DoubleSpend
    let s2 = transfer::transfer(token, &mut ns);
    assert!(s2.is_err());
}

#[test]
fn test_recursion_bound() {
    let mint = setup_mint(2, 3, 10);
    let token = mint.issue(100, &[1, 2], None).unwrap();
    let mut ns = NullifierSet::new();
    let mut current = token;
    for _ in 0..10 { current = transfer::transfer(current, &mut ns).unwrap().token; }
    assert!(transfer::transfer(current, &mut ns).is_err());
}

#[test]
fn test_tampered_value() {
    let mint = setup_mint(2, 3, 20);
    let mut token = mint.issue(1000, &[1, 2], None).unwrap();
    token.value = 9999;
    let vr = verify::verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0);
    assert!(!vr.all_valid());
}

#[test]
fn test_wrong_mint() {
    let m1 = setup_mint(2, 3, 20);
    let m2 = setup_mint(2, 3, 20);
    let token = m1.issue(1000, &[1, 2], None).unwrap();
    let vr = verify::verify_token(&token, &m2.group_public_key(), &m1.pedersen, &m1.credential_issuer.pedersen, 0);
    assert!(!vr.signature_valid);
}

#[test]
fn test_stress_100_tokens() {
    let mint = setup_mint(2, 3, 50);
    for _ in 0..100 {
        let token = mint.issue(1000, &[1, 3], Some(&test_attrs())).unwrap();
        let vr = verify::verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0);
        assert!(vr.all_valid());
    }
}

#[test]
fn test_stress_long_chain() {
    let mint = setup_mint(2, 3, 200);
    let token = mint.issue(1000, &[2, 3], None).unwrap();
    let mut ns = NullifierSet::new();
    let mut current = token;
    for _ in 0..200 { current = transfer::transfer(current, &mut ns).unwrap().token; }
    assert_eq!(current.fold_proof.steps, 200);
    let vr = verify::verify_token(&current, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0);
    assert!(vr.all_valid());
}

#[test]
fn test_multiple_tokens_independent() {
    let mint = setup_mint(2, 3, 20);
    let mut ns = NullifierSet::new();
    for i in 0u64..10 {
        let token = mint.issue(100 * (i + 1), &[1, 2], Some(&test_attrs())).unwrap();
        let mut c = token;
        for _ in 0..3 {
            let r = transfer::transfer(c, &mut ns).unwrap();
            c = r.token;
        }
        let vr = verify::verify_token(&c, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0);
        assert!(vr.all_valid());
    }
    assert_eq!(ns.len(), 30);
}
