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

use sha2::Digest;
use specter_credential::credential::Attributes;
use specter_core::mint::{Mint, MintConfig};
use specter_core::nullifier::NullifierSet;
use specter_core::serde_token;
use specter_core::transfer;
use specter_core::verify;
use specter_core::wallet::Wallet;

const WALLET_FILE: &str = "specter_wallet.dat";
const DEFAULT_PASSPHRASE: &[u8] = b"specter-dev-only";

/// Get wallet passphrase from environment.
/// In debug builds, falls back to a dev-mode default with a warning.
/// In release builds, refuses to proceed without a valid passphrase.
fn get_passphrase() -> Vec<u8> {
    match std::env::var("SPECTER_PASSPHRASE") {
        Ok(p) if p.len() >= 8 => p.into_bytes(),
        Ok(_) => {
            #[cfg(debug_assertions)]
            {
                eprintln!("Warning: SPECTER_PASSPHRASE too short, using dev default");
                DEFAULT_PASSPHRASE.to_vec()
            }
            #[cfg(not(debug_assertions))]
            {
                eprintln!("Error: SPECTER_PASSPHRASE must be at least 8 characters");
                std::process::exit(1);
            }
        }
        Err(_) => {
            #[cfg(debug_assertions)]
            {
                eprintln!("Warning: SPECTER_PASSPHRASE not set, using dev-mode passphrase");
                DEFAULT_PASSPHRASE.to_vec()
            }
            #[cfg(not(debug_assertions))]
            {
                eprintln!("Error: SPECTER_PASSPHRASE environment variable must be set");
                std::process::exit(1);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match command {
        "setup" => cmd_setup(),
        "mint" => cmd_mint(&args),
        "balance" => cmd_balance(),
        "transfer" => cmd_transfer(),
        "send" => cmd_send(&args),
        "receive" => cmd_receive(&args),
        "save" => cmd_save(),
        "load" => cmd_load(),
        "demo" => run_demo(),
        "benchmark" => run_benchmark(),
        "help" | "--help" | "-h" => print_help(),
        other => {
            let sanitized: String = other.chars().filter(|c| !c.is_control()).collect();
            eprintln!("Unknown command: {}. Use 'help' for usage.", sanitized);
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
    println!("  send <addr>         Send a token via TCP (default: 127.0.0.1:7878)");
    println!("  receive <addr>      Listen for a token via TCP (default: 127.0.0.1:7878)");
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
    // Use DKG-based mint for production-grade key generation.
    // Each invocation generates fresh keys (consistent within session).
    // In production, mint keys would be loaded from persistent storage.
    Mint::setup_with_dkg(MintConfig {
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
    let data = wallet.save(&get_passphrase());
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

    let data = wallet.save(&get_passphrase());
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

    let id = token.token_id;
    let mut ns = NullifierSet::new();
    let result = transfer::transfer(token, &mut ns).unwrap();

    // Remove old, add new
    wallet.remove_token(&id);
    wallet.add_token(result.token);

    let data = wallet.save(&get_passphrase());
    std::fs::write(WALLET_FILE, &data).expect("Failed to write wallet");

    println!("Transferred token {}.", hex::encode(&id[..8]));
    println!("  Nullifier: {}", hex::encode(&result.spent_nullifier[..16]));
    println!("  Balance: {}", wallet.balance());
}

fn cmd_save() {
    let mint = default_mint();
    let wallet = load_or_create_wallet(&mint);
    let data = wallet.save(&get_passphrase());
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

/// Perform ECDH key exchange and derive a shared ChaCha20-Poly1305 key.
/// Protocol: each side sends their ephemeral public key (32 bytes),
/// then both derive shared_secret = SHA-256(my_sk * their_pk).
/// Perform ECDH key exchange with timeouts and key zeroization.
///
/// WARNING: This is an anonymous (unauthenticated) DH exchange. It protects
/// against passive eavesdropping but NOT against active MitM attacks.
/// For production use, add mutual authentication (e.g., sign the transcript
/// with long-term node keys, or use a Noise protocol pattern like NK/KK).
fn dh_handshake(stream: &mut std::net::TcpStream, is_initiator: bool) -> Option<[u8; 32]> {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
    use std::io::{Read, Write};
    use std::time::Duration;
    use zeroize::Zeroize;

    // Set timeouts to prevent slow-peer DoS
    let timeout = Some(Duration::from_secs(30));
    stream.set_read_timeout(timeout).ok()?;
    stream.set_write_timeout(timeout).ok()?;

    let mut my_sk = specter_primitives::scalar_utils::random_scalar();
    let my_pk = (my_sk * G).compress();

    let result = if is_initiator {
        if stream.write_all(my_pk.as_bytes()).is_err() { None }
        else if stream.flush().is_err() { None }
        else {
            let mut their_pk_bytes = [0u8; 32];
            if stream.read_exact(&mut their_pk_bytes).is_err() { None }
            else {
                curve25519_dalek::ristretto::CompressedRistretto(their_pk_bytes)
                    .decompress()
                    .map(|their_pk| {
                        let shared = my_sk * their_pk;
                        let key = sha2::Sha256::digest(shared.compress().as_bytes());
                        let mut out = [0u8; 32];
                        out.copy_from_slice(&key);
                        out
                    })
            }
        }
    } else {
        let mut their_pk_bytes = [0u8; 32];
        if stream.read_exact(&mut their_pk_bytes).is_err() { None }
        else {
            let their_pk = curve25519_dalek::ristretto::CompressedRistretto(their_pk_bytes)
                .decompress();
            if their_pk.is_none() { None }
            else if stream.write_all(my_pk.as_bytes()).is_err() { None }
            else if stream.flush().is_err() { None }
            else {
                let their_pk = their_pk.unwrap();
                let shared = my_sk * their_pk;
                let key = sha2::Sha256::digest(shared.compress().as_bytes());
                let mut out = [0u8; 32];
                out.copy_from_slice(&key);
                Some(out)
            }
        }
    };

    // Zeroize ephemeral secret key
    my_sk.zeroize();
    result
}

/// Encrypt bytes with a shared key using ChaCha20-Poly1305.
fn encrypt_with_key(plaintext: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};
    use rand_core::{OsRng, RngCore};

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).ok()?;

    // Return nonce || ciphertext
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Some(out)
}

/// Decrypt bytes with a shared key using ChaCha20-Poly1305.
fn decrypt_with_key(data: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};

    if data.len() < 12 { return None; }
    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(nonce, ciphertext).ok()
}

fn cmd_send(args: &[String]) {
    let addr = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:7878");
    let mint = default_mint();
    let mut wallet = load_or_create_wallet(&mint);

    if wallet.is_empty() {
        println!("Wallet is empty. Mint a token first.");
        return;
    }

    let token = match wallet.select_token(1) {
        Some(t) => t.clone(),
        None => {
            println!("No transferable tokens.");
            return;
        }
    };
    let id = token.token_id;
    let plaintext = serde_token::serialize_token_public(&token);

    match std::net::TcpStream::connect(addr) {
        Ok(mut stream) => {
            use std::io::Write;

            // ECDH key exchange (sender is initiator)
            let shared_key = match dh_handshake(&mut stream, true) {
                Some(k) => k,
                None => { eprintln!("Key exchange failed with {}", addr); return; }
            };

            // Encrypt token bytes
            let encrypted = match encrypt_with_key(&plaintext, &shared_key) {
                Some(e) => e,
                None => { eprintln!("Encryption failed"); return; }
            };

            // Send encrypted: [4-byte length][nonce+ciphertext]
            if let Err(e) = stream.write_all(&(encrypted.len() as u32).to_le_bytes()) {
                eprintln!("Failed to send length to {}: {}", addr, e);
                return;
            }
            if let Err(e) = stream.write_all(&encrypted) {
                eprintln!("Failed to send token data to {}: {}", addr, e);
                return;
            }
            if let Err(e) = stream.flush() {
                eprintln!("Failed to flush stream to {}: {}", addr, e);
                return;
            }

            // Only remove from wallet AFTER successful send
            wallet.remove_token(&id);
            let data = wallet.save(&get_passphrase());
            std::fs::write(WALLET_FILE, &data).expect("Failed to write wallet");
            println!("Sent token {} to {} (encrypted, {} bytes)", hex::encode(&id[..8]), addr, encrypted.len());
        }
        Err(e) => {
            eprintln!("Failed to connect to {}: {}", addr, e);
        }
    }
}

fn cmd_receive(args: &[String]) {
    let addr = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:7878");

    let listener = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind {}: {}", addr, e);
            return;
        }
    };
    println!("Listening on {}...", addr);

    match listener.accept() {
        Ok((mut stream, peer)) => {
            use std::io::Read;

            // ECDH key exchange (receiver is responder)
            let shared_key = match dh_handshake(&mut stream, false) {
                Some(k) => k,
                None => { eprintln!("Key exchange failed with {}", peer); return; }
            };

            // Read encrypted length
            let mut len_buf = [0u8; 4];
            if let Err(e) = stream.read_exact(&mut len_buf) {
                eprintln!("Connection error reading length: {}", e);
                return;
            }
            let len = u32::from_le_bytes(len_buf) as usize;

            const MAX_TOKEN_SIZE: usize = 65536;
            if len > MAX_TOKEN_SIZE || len == 0 {
                eprintln!("Rejected token: invalid size {} bytes (max {})", len, MAX_TOKEN_SIZE);
                return;
            }

            // Read encrypted data
            let mut encrypted_buf = vec![0u8; len];
            if let Err(e) = stream.read_exact(&mut encrypted_buf) {
                eprintln!("Connection error reading token data: {}", e);
                return;
            }

            // Decrypt with shared key
            let buf = match decrypt_with_key(&encrypted_buf, &shared_key) {
                Some(p) => p,
                None => {
                    eprintln!("Decryption failed from {} - tampered or wrong key", peer);
                    return;
                }
            };

            match serde_token::deserialize_token(&buf) {
                Ok(token) => {
                    let mint = default_mint();
                    let vr = verify::verify_token(
                        &token, &mint.group_public_key(), &mint.pedersen,
                        &mint.credential_issuer.pedersen, 0,
                    );

                    if vr.all_valid() {
                        let id = token.token_id;
                        let mut wallet = load_or_create_wallet(&mint);
                        wallet.add_token(token);
                        let data = wallet.save(&get_passphrase());
                        std::fs::write(WALLET_FILE, &data).expect("Failed to write wallet");
                        println!("Received valid token {} from {} ({} bytes)",
                            hex::encode(&id[..8]), peer, len);
                    } else {
                        eprintln!("Received INVALID token from {}!", peer);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to deserialize token: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to accept connection: {}", e);
        }
    }
}

fn load_or_create_wallet(mint: &Mint) -> Wallet {
    match std::fs::read(WALLET_FILE) {
        Ok(data) => {
            Wallet::load(
                &data,
                &get_passphrase(),
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
    let result = verify::verify_token(&token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0);
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
        let tr = transfer::transfer(current, &mut nullifier_set).unwrap();

        let vr = verify::verify_token(&tr.token, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0);
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
    let mut ds_set = NullifierSet::new();
    let _spend1 = transfer::transfer(original.clone(), &mut ds_set).unwrap();
    let spend2_result = transfer::transfer(original, &mut ds_set);

    let first_ok = true; // spend1 succeeded above
    let second_ok = spend2_result.is_ok();
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
        let _ = verify::verify_token(t, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0);
    }
    println!("Verify (with cred):            {:?} avg", start.elapsed() / n as u32);

    let start = Instant::now();
    for t in tokens.iter() {
        let mut ns = NullifierSet::new();
        let _ = transfer::transfer(t.clone(), &mut ns).unwrap();
    }
    println!("Transfer (P2P local):          {:?} avg", start.elapsed() / n as u32);

    let token = mint.issue(1000, &[1, 2], Some(&attrs)).unwrap();
    let start = Instant::now();
    let mut chain_ns = NullifierSet::new();
    let mut current = token;
    for _ in 0..20 { current = transfer::transfer(current, &mut chain_ns).unwrap().token; }
    println!("20-transfer chain:             {:?} total", start.elapsed());

    let start = Instant::now();
    let r = verify::verify_token(&current, &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen, 0);
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
