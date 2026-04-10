//! End-to-end integration tests for the Specter protocol.
//!
//! Tests the full lifecycle: mint → transfer → verify → double-spend detection.

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

// ─── Full Lifecycle Tests ───────────────────────────────────────────────────

#[test]
fn test_full_lifecycle_2_of_3() {
    let mint = setup_mint(2, 3, 20);
    let token = mint.issue(1000, &[1, 2]).unwrap();

    // Verify fresh token
    let vr = verify::verify_token(&token, &mint.group_public_key(), &mint.pedersen);
    assert!(vr.all_valid());

    // Transfer 10 times
    let mut current = token;
    let mut nullifier_set = NullifierSet::new();

    for i in 0..10 {
        let result = transfer::transfer(&current).unwrap();
        assert!(
            transfer::check_double_spend(&mut nullifier_set, &result.spent_nullifier).is_ok(),
            "false positive double-spend at step {}",
            i
        );

        let vr = verify::verify_token(&result.token, &mint.group_public_key(), &mint.pedersen);
        assert!(vr.all_valid(), "verification failed at step {}", i);

        current = result.token;
    }

    assert_eq!(current.transfer_count, 10);
    assert_eq!(current.value, 1000);
    assert_eq!(nullifier_set.len(), 10);
}

#[test]
fn test_full_lifecycle_3_of_5() {
    let mint = setup_mint(3, 5, 50);

    // Issue with different signer subsets
    let t1 = mint.issue(500, &[1, 2, 3]).unwrap();
    let t2 = mint.issue(200, &[3, 4, 5]).unwrap();
    let t3 = mint.issue(800, &[1, 3, 5]).unwrap();

    for token in [&t1, &t2, &t3] {
        let vr = verify::verify_token(token, &mint.group_public_key(), &mint.pedersen);
        assert!(vr.all_valid());
    }

    // Transfer t1 through 20 hops
    let mut current = t1;
    for _ in 0..20 {
        current = transfer::transfer(&current).unwrap().token;
    }
    let vr = verify::verify_token(&current, &mint.group_public_key(), &mint.pedersen);
    assert!(vr.all_valid());
    assert_eq!(current.transfer_count, 20);
}

// ─── Double-Spend Detection ────────────────────────────────────────────────

#[test]
fn test_double_spend_same_token_two_recipients() {
    let mint = setup_mint(2, 3, 20);
    let token = mint.issue(1000, &[1, 2]).unwrap();

    // Alice tries to spend the same token to Bob AND Carol
    let to_bob = transfer::transfer(&token).unwrap();
    let to_carol = transfer::transfer(&token).unwrap();

    // Same nullifier (same owner secret + token_id)
    assert_eq!(to_bob.spent_nullifier, to_carol.spent_nullifier);

    // Network detects double-spend
    let mut set = NullifierSet::new();
    assert!(transfer::check_double_spend(&mut set, &to_bob.spent_nullifier).is_ok());
    assert!(transfer::check_double_spend(&mut set, &to_carol.spent_nullifier).is_err());
}

#[test]
fn test_no_false_positives_in_chain() {
    let mint = setup_mint(2, 3, 100);
    let token = mint.issue(100, &[1, 2]).unwrap();

    let mut current = token;
    let mut set = NullifierSet::new();

    // 50 sequential transfers — no double-spending
    for i in 0..50 {
        let result = transfer::transfer(&current).unwrap();
        assert!(
            transfer::check_double_spend(&mut set, &result.spent_nullifier).is_ok(),
            "false positive at step {}",
            i
        );
        current = result.token;
    }
    assert_eq!(set.len(), 50);
}

// ─── Recursion Bound Enforcement ───────────────────────────────────────────

#[test]
fn test_recursion_bound_exact() {
    let mint = setup_mint(2, 3, 10);
    let token = mint.issue(100, &[1, 2]).unwrap();

    let mut current = token;
    for _ in 0..10 {
        current = transfer::transfer(&current).unwrap().token;
    }

    // 11th transfer should fail
    assert!(transfer::transfer(&current).is_err());
}

// ─── Tamper Detection ──────────────────────────────────────────────────────

#[test]
fn test_tampered_value_detected() {
    let mint = setup_mint(2, 3, 20);
    let mut token = mint.issue(1000, &[1, 2]).unwrap();

    // Tamper with value
    token.value = 9999;

    let vr = verify::verify_token(&token, &mint.group_public_key(), &mint.pedersen);
    assert!(!vr.value_valid);
    assert!(!vr.all_valid());
}

#[test]
fn test_wrong_mint_key_detected() {
    let mint1 = setup_mint(2, 3, 20);
    let mint2 = setup_mint(2, 3, 20);
    let token = mint1.issue(1000, &[1, 2]).unwrap();

    // Verify against wrong mint
    let vr = verify::verify_token(&token, &mint2.group_public_key(), &mint1.pedersen);
    assert!(!vr.signature_valid);
    assert!(!vr.all_valid());
}

// ─── Multiple Tokens ───────────────────────────────────────────────────────

#[test]
fn test_multiple_tokens_independent() {
    let mint = setup_mint(2, 3, 20);
    let mut nullifier_set = NullifierSet::new();

    // Mint 10 tokens and transfer each 3 times
    for i in 0..10 {
        let token = mint.issue(100 * (i + 1), &[1, 2]).unwrap();
        let mut current = token;

        for _ in 0..3 {
            let result = transfer::transfer(&current).unwrap();
            assert!(transfer::check_double_spend(&mut nullifier_set, &result.spent_nullifier).is_ok());
            current = result.token;
        }

        let vr = verify::verify_token(&current, &mint.group_public_key(), &mint.pedersen);
        assert!(vr.all_valid(), "token {} failed verification", i);
    }

    // 10 tokens * 3 transfers = 30 nullifiers
    assert_eq!(nullifier_set.len(), 30);
}

// ─── Stress Tests ──────────────────────────────────────────────────────────

#[test]
fn test_stress_100_tokens() {
    let mint = setup_mint(2, 3, 50);

    for _ in 0..100 {
        let token = mint.issue(1000, &[1, 3]).unwrap();
        let vr = verify::verify_token(&token, &mint.group_public_key(), &mint.pedersen);
        assert!(vr.all_valid());
    }
}

#[test]
fn test_stress_long_transfer_chain() {
    let mint = setup_mint(2, 3, 200);
    let token = mint.issue(1000, &[2, 3]).unwrap();

    let mut current = token;
    for _ in 0..200 {
        current = transfer::transfer(&current).unwrap().token;
    }

    let vr = verify::verify_token(&current, &mint.group_public_key(), &mint.pedersen);
    assert!(vr.all_valid());
    assert_eq!(current.transfer_count, 200);
    assert!(current.needs_renewal());
}
