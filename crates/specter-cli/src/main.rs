//! Specter CLI — demo tool for the Proof-Carrying Token protocol.
//!
//! Usage:
//!   specter-cli demo          Run a full demonstration of the protocol
//!   specter-cli benchmark     Run basic timing measurements

use std::time::Instant;

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

fn run_demo() {
    println!("=== Specter Protocol Demo ===");
    println!();

    // Setup
    println!("[1/5] Setting up threshold mint (2-of-3)...");
    let mint = Mint::setup(MintConfig {
        threshold: 2,
        total_signers: 3,
        recursion_bound: 20,
    });
    println!("  Group public key: {}", hex::encode(mint.group_public_key().compress().as_bytes()));
    println!();

    // Mint a token
    println!("[2/5] Minting token (value: 1000, signers: [1, 3])...");
    let token = mint.issue(1000, &[1, 3]).unwrap();
    println!("  Token ID:         {}", hex::encode(&token.token_id));
    println!("  Value:            {}", token.value);
    println!("  Transfer count:   {}/{}", token.transfer_count, token.recursion_bound);
    println!("  Estimated size:   {} bytes", token.estimated_size());
    println!();

    // Verify
    println!("[3/5] Verifying freshly minted token...");
    let result = verify::verify_token(&token, &mint.group_public_key(), &mint.pedersen);
    println!("  Signature valid:  {}", result.signature_valid);
    println!("  Value valid:      {}", result.value_valid);
    println!("  Within bound:     {}", result.within_bound);
    println!("  ALL VALID:        {}", result.all_valid());
    println!();

    // Transfer chain
    println!("[4/5] Transferring token 5 times...");
    let mut current = token;
    let mut nullifier_set = NullifierSet::new();

    for i in 1..=5 {
        let tr = transfer::transfer(&current).unwrap();
        transfer::check_double_spend(&mut nullifier_set, &tr.spent_nullifier).unwrap();

        let vr = verify::verify_token(&tr.token, &mint.group_public_key(), &mint.pedersen);
        println!(
            "  Transfer {}: count={}/{}, valid={}, nullifier={}...",
            i,
            tr.token.transfer_count,
            tr.token.recursion_bound,
            vr.all_valid(),
            hex::encode(&tr.spent_nullifier[..8]),
        );
        current = tr.token;
    }
    println!();

    // Double-spend detection
    println!("[5/5] Demonstrating double-spend detection...");
    let original_token = mint.issue(500, &[2, 3]).unwrap();

    let spend1 = transfer::transfer(&original_token).unwrap();
    let spend2 = transfer::transfer(&original_token).unwrap();

    println!("  Spend 1 nullifier: {}", hex::encode(&spend1.spent_nullifier[..16]));
    println!("  Spend 2 nullifier: {}", hex::encode(&spend2.spent_nullifier[..16]));
    println!("  Same nullifier:    {}", spend1.spent_nullifier == spend2.spent_nullifier);

    let mut ds_set = NullifierSet::new();
    let first_ok = transfer::check_double_spend(&mut ds_set, &spend1.spent_nullifier).is_ok();
    let second_ok = transfer::check_double_spend(&mut ds_set, &spend2.spent_nullifier).is_ok();
    println!("  First spend:       {} (should be true)", first_ok);
    println!("  Second spend:      {} (should be false - DOUBLE SPEND!)", second_ok);
    println!();

    println!("=== Demo Complete ===");
}

fn run_benchmark() {
    println!("=== Specter Protocol Benchmark ===");
    println!();

    let iterations = 50;

    // Benchmark mint setup
    let start = Instant::now();
    let mint = Mint::setup(MintConfig {
        threshold: 2,
        total_signers: 3,
        recursion_bound: 20,
    });
    let setup_time = start.elapsed();
    println!("Mint setup (2-of-3): {:?}", setup_time);

    // Benchmark token issuance
    let start = Instant::now();
    let mut tokens = Vec::new();
    for _ in 0..iterations {
        tokens.push(mint.issue(1000, &[1, 2]).unwrap());
    }
    let issue_time = start.elapsed();
    println!(
        "Token issuance:      {:?} avg ({} iterations)",
        issue_time / iterations as u32,
        iterations
    );

    // Benchmark verification
    let start = Instant::now();
    for token in &tokens {
        let _ = verify::verify_token(token, &mint.group_public_key(), &mint.pedersen);
    }
    let verify_time = start.elapsed();
    println!(
        "Token verification:  {:?} avg ({} iterations)",
        verify_time / iterations as u32,
        iterations
    );

    // Benchmark transfer
    let start = Instant::now();
    for token in &tokens {
        let _ = transfer::transfer(token).unwrap();
    }
    let transfer_time = start.elapsed();
    println!(
        "Token transfer:      {:?} avg ({} iterations)",
        transfer_time / iterations as u32,
        iterations
    );

    // Benchmark chain of 20 transfers
    let token = mint.issue(1000, &[1, 2]).unwrap();
    let start = Instant::now();
    let mut current = token;
    for _ in 0..20 {
        let result = transfer::transfer(&current).unwrap();
        current = result.token;
    }
    let chain_time = start.elapsed();
    println!("20-transfer chain:   {:?} total", chain_time);

    // Verify the final token
    let start = Instant::now();
    let result = verify::verify_token(&current, &mint.group_public_key(), &mint.pedersen);
    let final_verify = start.elapsed();
    println!("Final verification:  {:?} (valid={})", final_verify, result.all_valid());

    println!();
    println!("Token estimated size: {} bytes", current.estimated_size());
    println!("=== Benchmark Complete ===");
}
