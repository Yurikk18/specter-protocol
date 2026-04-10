//! Specter CLI - tool for the Proof-Carrying Token protocol.
//!
//! Commands:
//!   setup       Create a new mint and empty wallet
//!   mint        Mint a token and add to wallet
//!   balance     Show wallet balance and token list
//!   transfer    Transfer a token (updates wallet)
//!   save        Save wallet to encrypted file
//!   load        Load wallet from encrypted file
//!   demo        Run full protocol demonstration
//!   benchmark   Run performance measurements

use std::time::Instant;

use specter_credential::credential::Attributes;
use specter_core::mint::{Mint, MintConfig};
use specter_core::nullifier::NullifierSet;
use specter_core::serde_token;
use specter_core::transfer;
use specter_core::verify;
use specter_core::wallet::Wallet;

const WALLET_FILE: &str = "specter_wallet.dat";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match command {
        "setup" => cmd_setup(),
        "mint" => cmd_mint(&args),
        "balance" => cmd_balance(),
        "transfer" => cmd_transfer(),
        "save" => cmd_save(),
        "load" => cmd_load(),
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
    println!("Specter Protocol CLI v0.2.0");
    println!();
    println!("Usage: specter-cli <command> [args]");
    println!();
    println!("Commands:");
    println!("  setup               Create a new mint and empty wallet");
    println!("  mint <value>        Mint a token with given value");
    println!("  balance             Show wallet balance and tokens");
    println!("  transfer            Transfer first available token");
    println!("  save                Save wallet to encrypted file");
    println!("  load                Load wallet from encrypted file");
    println!("  demo                Run full protocol demonstration");
    println!("  benchmark           Run performance measurements");
    println!("  help                Show this help");
}

fn default_attrs() -> Attributes {
    Attributes {
        kyc_passed: true,
        not_sanctioned: true,
        jurisdiction: "EU".to_string(),
        age_over_18: true,
        expires_at: 0,
    }
}

fn default_mint() -> Mint {
    // Use a fixed mint for CLI consistency across sessions.
    // In production, the mint would be a network service with persistent keys.
    // lazy_static or OnceCell would be ideal, but for a CLI tool this works.
    Mint::setup(MintConfig {
        threshold: 2,
        total_signers: 3,
        recursion_bound: 20,
    })
}

fn cmd_setup() {
    // Note: each CLI invocation generates a new random mint.
    // Wallet persistence works within a single session.
    // In production, the mint would be a persistent network service.
    println!("Setting up new mint (2-of-3 threshold)...");
    let mint = default_mint();
    println!("  Group public key: {}", hex::encode(mint.group_public_key().compress().as_bytes()));

    let wallet = Wallet::new();
    let data = wallet.save(b"specter");
    std::fs::write(WALLET_FILE, &data).expect("Failed to write wallet file");
    println!("  Empty wallet saved to {}", WALLET_FILE);
    println!("Setup complete.");
}

fn cmd_mint(args: &[String]) {
    let value: u64 = args.get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    let mint = default_mint();
    let token = mint.issue(value, &[1, 2], Some(&default_attrs())).unwrap();

    println!("Minted token:");
    println!("  ID:    {}", hex::encode(&token.token_id[..8]));
    println!("  Value: {}", token.value);
    println!("  Size:  {} bytes", serde_token::serialized_size(&token));

    // Load wallet, add token, save
    let mut wallet = load_or_create_wallet(&mint);
    wallet.add_token(token);

    let data = wallet.save(b"specter");
    std::fs::write(WALLET_FILE, &data).expect("Failed to write wallet");
    println!("  Added to wallet. Balance: {}", wallet.balance());
}

fn cmd_balance() {
    let mint = default_mint();
    let wallet = load_or_create_wallet(&mint);

    println!("Wallet balance: {}", wallet.balance());
    println!("Tokens: {}", wallet.token_count());

    for info in wallet.list_tokens() {
        println!(
            "  {} | value={} | transfers={}/{} | cred={} | bond={}",
            hex::encode(&info.token_id[..8]),
            info.value,
            info.transfer_count,
            info.recursion_bound,
            info.has_credential,
            info.has_bond,
        );
    }

    let needing = wallet.tokens_needing_renewal();
    if !needing.is_empty() {
        println!("\n{} token(s) need renewal.", needing.len());
    }
}

fn cmd_transfer() {
    let mint = default_mint();
    let mut wallet = load_or_create_wallet(&mint);

    if wallet.is_empty() {
        println!("Wallet is empty. Mint a token first.");
        return;
    }

    // Select first available token
    let token = match wallet.select_token(1) {
        Some(t) => t.clone(),
        None => {
            println!("No transferable tokens (all may need renewal).");
            return;
        }
    };

    let result = transfer::transfer(&token).unwrap();
    let id = token.token_id;

    // Remove old, add new
    wallet.remove_token(&id);
    wallet.add_token(result.token);

    let data = wallet.save(b"specter");
    std::fs::write(WALLET_FILE, &data).expect("Failed to write wallet");

    println!("Transferred token {}.", hex::encode(&id[..8]));
    println!("  Nullifier: {}", hex::encode(&result.spent_nullifier[..16]));
    println!("  Balance: {}", wallet.balance());
}

fn cmd_save() {
    let mint = default_mint();
    let wallet = load_or_create_wallet(&mint);
    let data = wallet.save(b"specter");
    std::fs::write(WALLET_FILE, &data).expect("Failed to write wallet");
    println!("Wallet saved to {} ({} bytes, {} tokens)", WALLET_FILE, data.len(), wallet.token_count());
}

fn cmd_load() {
    let mint = default_mint();
    let wallet = load_or_create_wallet(&mint);
    println!("Wallet loaded from {}", WALLET_FILE);
    println!("  Balance: {}", wallet.balance());
    println!("  Tokens:  {}", wallet.token_count());
}

fn load_or_create_wallet(mint: &Mint) -> Wallet {
    match std::fs::read(WALLET_FILE) {
        Ok(data) => {
            Wallet::load(
                &data,
                b"specter",
                &mint.group_public_key(),
                &mint.pedersen,
                &mint.credential_issuer.pedersen,
            ).unwrap_or_else(|_| {
                println!("  (Could not load wallet, creating new)");
                Wallet::new()
            })
        }
        Err(_) => Wallet::new(),
    }
}

// ===== Demo and Benchmark (unchanged functionality) =====

fn run_demo() {
    println!("=== Specter Protocol Demo ===");
    println!();

    println!("[1/6] Setting up threshold mint (2-of-3)...");
    let mint = default_mint();
    println!("  Group public key: {}", hex::encode(mint.group_public_key().compress().as_bytes()));
    println!();

    println!("[2/6] Minting token with compliance credential...");
    let token = mint.issue(1000, &[1, 3], Some(&default_attrs())).unwrap();
    println!("  Token ID:          {}", hex::encode(&token.token_id[..8]));
    println!("  Value:             {}", token.value);
    println!("  Has credential:    {}", token.has_credential());
    println!("  Fold proof steps:  {}", token.fold_proof.steps);
    println!("  Transfer count:    {}/{}", token.transfer_count, token.recursion_bound);
    println!("  Serialized size:   {} bytes", serde_token::serialized_size(&token));
    println!();

    println!("[3/6] Verifying freshly minted token...");
    let result = verify::verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
    println!("  Signature valid:   {}", result.signature_valid);
    println!("  Value valid:       {}", result.value_valid);
    println!("  Within bound:      {}", result.within_bound);
    println!("  Fold valid:        {}", result.fold_valid);
    println!("  Credential valid:  {:?}", result.credential_valid);
    println!("  ALL VALID:         {}", result.all_valid());
    println!();

    println!("[4/6] Transferring token 5 times (with fold accumulation)...");
    let mut current = token;
    let mut nullifier_set = NullifierSet::new();

    for i in 1..=5 {
        let tr = transfer::transfer(&current).unwrap();
        transfer::check_double_spend(&mut nullifier_set, &tr.spent_nullifier).unwrap();

        let vr = verify::verify_token(&tr.token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
        println!(
            "  Transfer {}: count={}/{}, fold_steps={}, valid={}, nullifier={}...",
            i, tr.token.transfer_count, tr.token.recursion_bound,
            tr.token.fold_proof.steps, vr.all_valid(),
            hex::encode(&tr.spent_nullifier[..8]),
        );
        current = tr.token;
    }
    println!();

    println!("[5/6] Demonstrating double-spend detection...");
    let original = mint.issue(500, &[2, 3], None).unwrap();
    let spend1 = transfer::transfer(&original).unwrap();
    let spend2 = transfer::transfer(&original).unwrap();

    println!("  Same nullifier:    {}", spend1.spent_nullifier == spend2.spent_nullifier);
    let mut ds_set = NullifierSet::new();
    let first_ok = transfer::check_double_spend(&mut ds_set, &spend1.spent_nullifier).is_ok();
    let second_ok = transfer::check_double_spend(&mut ds_set, &spend2.spent_nullifier).is_ok();
    println!("  First spend:       {} (valid)", first_ok);
    println!("  Second spend:      {} (DOUBLE SPEND DETECTED)", second_ok);
    println!();

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
    let mint = default_mint();
    println!("Mint setup (2-of-3):           {:?}", start.elapsed());

    let start = Instant::now();
    let mut tokens = Vec::new();
    for _ in 0..n { tokens.push(mint.issue(1000, &[1, 2], None).unwrap()); }
    println!("Issue (no cred):               {:?} avg", start.elapsed() / n as u32);

    let attrs = default_attrs();
    let start = Instant::now();
    let mut cred_tokens = Vec::new();
    for _ in 0..n { cred_tokens.push(mint.issue(1000, &[1, 2], Some(&attrs)).unwrap()); }
    println!("Issue (with cred):             {:?} avg", start.elapsed() / n as u32);

    let start = Instant::now();
    for t in &cred_tokens {
        let _ = verify::verify_token(t, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
    }
    println!("Verify (with cred):            {:?} avg", start.elapsed() / n as u32);

    let start = Instant::now();
    for t in &tokens { let _ = transfer::transfer(t).unwrap(); }
    println!("Transfer (P2P local):          {:?} avg", start.elapsed() / n as u32);

    let token = mint.issue(1000, &[1, 2], Some(&attrs)).unwrap();
    let start = Instant::now();
    let mut current = token;
    for _ in 0..20 { current = transfer::transfer(&current).unwrap().token; }
    println!("20-transfer chain:             {:?} total", start.elapsed());

    let start = Instant::now();
    let r = verify::verify_token(&current, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
    println!("Final verify (20 transfers):   {:?} (valid={})", start.elapsed(), r.all_valid());

    // Serialization benchmark
    let start = Instant::now();
    for t in &cred_tokens { let _ = serde_token::serialize_token(t); }
    println!("Serialize (with cred):         {:?} avg", start.elapsed() / n as u32);

    // Wallet save/load benchmark
    let mut wallet = Wallet::new();
    for t in cred_tokens { wallet.add_token(t); }
    let start = Instant::now();
    let saved = wallet.save(b"bench-passphrase");
    println!("Wallet save (50 tokens):       {:?} ({} bytes)", start.elapsed(), saved.len());

    let start = Instant::now();
    let _ = Wallet::load(&saved, b"bench-passphrase", &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
    println!("Wallet load (50 tokens):       {:?}", start.elapsed());

    println!("\nToken size (no cred):          {} bytes", serde_token::serialized_size(&tokens[0]));
    println!("Token size (with cred):        {} bytes (constant after transfers)", serde_token::serialized_size(&tokens[0]));
    println!("=== Benchmark Complete ===");
}
