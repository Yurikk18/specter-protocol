//! Specter CLI — demo tool for the Proof-Carrying Token protocol.

use std::time::Instant;

use specter_credential::credential::Attributes;
use specter_core::mint::{Mint, MintConfig};
use specter_core::nullifier::NullifierSet;
use specter_core::transfer;
use specter_core::verify;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("demo");

    match command {
        "demo" => run_demo(),
        "benchmark" => run_benchmark(),
        "help" | "--help" | "-h" => print_help(),
        other => {
            eprintln!("Unknown command: {}. Use 'help' for usage.", other);
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!("Specter Protocol CLI v0.1.0");
    println!();
    println!("Usage: specter-cli <command>");
    println!();
    println!("Commands:");
    println!("  demo        Run a full protocol demonstration");
    println!("  benchmark   Run basic timing measurements");
    println!("  help        Show this help message");
}

fn default_attrs() -> Attributes {
    Attributes {
        kyc_passed: true,
        not_sanctioned: true,
        jurisdiction: "EU".to_string(),
        age_over_18: true,
    }
}

fn run_demo() {
    println!("=== Specter Protocol Demo ===");
    println!();

    // Setup
    println!("[1/6] Setting up threshold mint (2-of-3)...");
    let mint = Mint::setup(MintConfig {
        threshold: 2,
        total_signers: 3,
        recursion_bound: 20,
    });
    println!("  Group public key: {}", hex::encode(mint.group_public_key().compress().as_bytes()));
    println!();

    // Mint with credential
    println!("[2/6] Minting token with compliance credential...");
    let token = mint.issue(1000, &[1, 3], Some(&default_attrs())).unwrap();
    println!("  Token ID:          {}", hex::encode(&token.token_id));
    println!("  Value:             {}", token.value);
    println!("  Has credential:    {}", token.has_credential());
    println!("  Fold proof steps:  {}", token.fold_proof.steps);
    println!("  Transfer count:    {}/{}", token.transfer_count, token.recursion_bound);
    println!("  Estimated size:    {} bytes", token.estimated_size());
    println!();

    // Verify
    println!("[3/6] Verifying freshly minted token...");
    let result = verify::verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
    println!("  Signature valid:   {}", result.signature_valid);
    println!("  Value valid:       {}", result.value_valid);
    println!("  Within bound:      {}", result.within_bound);
    println!("  Fold valid:        {}", result.fold_valid);
    println!("  Credential valid:  {:?}", result.credential_valid);
    println!("  ALL VALID:         {}", result.all_valid());
    println!();

    // Transfer chain
    println!("[4/6] Transferring token 5 times (with fold accumulation)...");
    let mut current = token;
    let mut nullifier_set = NullifierSet::new();

    for i in 1..=5 {
        let tr = transfer::transfer(&current).unwrap();
        transfer::check_double_spend(&mut nullifier_set, &tr.spent_nullifier).unwrap();

        let vr = verify::verify_token(&tr.token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
        println!(
            "  Transfer {}: count={}/{}, fold_steps={}, valid={}, nullifier={}...",
            i,
            tr.token.transfer_count,
            tr.token.recursion_bound,
            tr.token.fold_proof.steps,
            vr.all_valid(),
            hex::encode(&tr.spent_nullifier[..8]),
        );
        current = tr.token;
    }
    println!();

    // Double-spend detection
    println!("[5/6] Demonstrating double-spend detection...");
    let original = mint.issue(500, &[2, 3], None).unwrap();
    let spend1 = transfer::transfer(&original).unwrap();
    let spend2 = transfer::transfer(&original).unwrap();

    println!("  Spend 1 nullifier: {}", hex::encode(&spend1.spent_nullifier[..16]));
    println!("  Spend 2 nullifier: {}", hex::encode(&spend2.spent_nullifier[..16]));
    println!("  Same nullifier:    {}", spend1.spent_nullifier == spend2.spent_nullifier);

    let mut ds_set = NullifierSet::new();
    let first_ok = transfer::check_double_spend(&mut ds_set, &spend1.spent_nullifier).is_ok();
    let second_ok = transfer::check_double_spend(&mut ds_set, &spend2.spent_nullifier).is_ok();
    println!("  First spend:       {} (valid)", first_ok);
    println!("  Second spend:      {} (DOUBLE SPEND DETECTED)", second_ok);
    println!();

    // Credential selective disclosure
    println!("[6/6] Credential properties...");
    if let Some(cred) = &current.credential {
        println!("  KYC passed:        {}", cred.attributes.kyc_passed);
        println!("  Not sanctioned:    {}", cred.attributes.not_sanctioned);
        println!("  Jurisdiction:      {}", cred.attributes.jurisdiction);
        println!("  Age over 18:       {}", cred.attributes.age_over_18);
        println!("  (Verifier sees ONLY the ZK proof, not these values)");
    }
    println!();

    println!("=== Demo Complete ===");
}

fn run_benchmark() {
    println!("=== Specter Protocol Benchmark ===");
    println!();
    let n = 50;

    let start = Instant::now();
    let mint = Mint::setup(MintConfig { threshold: 2, total_signers: 3, recursion_bound: 20 });
    println!("Mint setup (2-of-3):           {:?}", start.elapsed());

    // Issuance without credential
    let start = Instant::now();
    let mut tokens = Vec::new();
    for _ in 0..n { tokens.push(mint.issue(1000, &[1, 2], None).unwrap()); }
    println!("Issue (no cred):               {:?} avg", start.elapsed() / n as u32);

    // Issuance with credential
    let attrs = default_attrs();
    let start = Instant::now();
    let mut cred_tokens = Vec::new();
    for _ in 0..n { cred_tokens.push(mint.issue(1000, &[1, 2], Some(&attrs)).unwrap()); }
    println!("Issue (with cred):             {:?} avg", start.elapsed() / n as u32);

    // Verification
    let start = Instant::now();
    for t in &cred_tokens { let _ = verify::verify_token(t, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen); }
    println!("Verify (with cred):            {:?} avg", start.elapsed() / n as u32);

    // Transfer
    let start = Instant::now();
    for t in &tokens { let _ = transfer::transfer(t).unwrap(); }
    println!("Transfer:                      {:?} avg", start.elapsed() / n as u32);

    // 20-transfer chain
    let token = mint.issue(1000, &[1, 2], Some(&attrs)).unwrap();
    let start = Instant::now();
    let mut current = token;
    for _ in 0..20 { current = transfer::transfer(&current).unwrap().token; }
    println!("20-transfer chain:             {:?} total", start.elapsed());

    let start = Instant::now();
    let r = verify::verify_token(&current, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
    println!("Final verify (20 transfers):   {:?} (valid={})", start.elapsed(), r.all_valid());

    println!("\nToken size (no cred):          {} bytes", tokens[0].estimated_size());
    println!("Token size (with cred):        {} bytes", cred_tokens[0].estimated_size());
    println!("=== Benchmark Complete ===");
}
