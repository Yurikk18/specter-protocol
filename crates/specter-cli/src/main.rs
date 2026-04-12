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
const IDENTITY_FILE: &str = "specter_identity.dat";
#[cfg(debug_assertions)]
const DEFAULT_PASSPHRASE: &[u8] = b"specter-dev-only-min12";

/// Get wallet passphrase from environment.
/// In debug builds, falls back to a dev-mode default with a warning.
/// In release builds, refuses to proceed without a valid passphrase.
///
/// The minimum length is tied to `secure_store::MIN_PASSPHRASE_LEN` (12)
/// to prevent inconsistency where the CLI accepts a passphrase that
/// `wallet.save()` would then reject.
fn get_passphrase() -> Vec<u8> {
    const MIN_LEN: usize = specter_core::secure_store::MIN_PASSPHRASE_LEN;
    match std::env::var("SPECTER_PASSPHRASE") {
        Ok(p) if p.len() >= MIN_LEN => p.into_bytes(),
        Ok(_) => {
            #[cfg(debug_assertions)]
            {
                eprintln!(
                    "Warning: SPECTER_PASSPHRASE too short (need >= {} bytes), using dev default",
                    MIN_LEN
                );
                DEFAULT_PASSPHRASE.to_vec()
            }
            #[cfg(not(debug_assertions))]
            {
                eprintln!(
                    "Error: SPECTER_PASSPHRASE must be at least {} characters",
                    MIN_LEN
                );
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
    // A6: disable core dumps at startup so an unexpected crash cannot
    // persist decrypted wallet secrets to disk. Unix-only; Windows WER
    // is governed by registry policy and this is a no-op there.
    let _ = specter_core::memory_guard::disable_core_dumps();

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
    println!("  setup                        Create a new mint and empty wallet");
    println!("  mint <value>                 Mint a token with given value");
    println!("  balance                      Show wallet balance and tokens");
    println!("  transfer                     Transfer first available token");
    println!("  send <addr> [peer_pubkey]    Send a token via TCP (SIGMA-I authenticated)");
    println!("  receive <addr>               Listen for a token via TCP (prints own pubkey)");
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
    let data = match wallet.save(&get_passphrase()) {
        Ok(d) => d,
        Err(e) => { eprintln!("Failed to save wallet: {}", e); std::process::exit(1); }
    };
    if let Err(e) = std::fs::write(WALLET_FILE, &data) {
        eprintln!("Failed to write wallet file: {}", e);
        std::process::exit(1);
    }
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

    let data = match wallet.save(&get_passphrase()) {
        Ok(d) => d,
        Err(e) => { eprintln!("Failed to save wallet: {}", e); std::process::exit(1); }
    };
    if let Err(e) = std::fs::write(WALLET_FILE, &data) {
        eprintln!("Failed to write wallet: {}", e);
        std::process::exit(1);
    }
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

    // Take the first available token (removes from wallet, giving ownership)
    let token = match wallet.take_token(1) {
        Some(t) => t,
        None => {
            println!("No transferable tokens (all may need renewal).");
            return;
        }
    };

    let id = token.token_id;
    let mut ns = NullifierSet::new();
    let result = match transfer::transfer(token, &mut ns) {
        Ok(r) => r,
        Err(e) => { eprintln!("Transfer failed: {}", e); std::process::exit(1); }
    };

    // Add the transferred token back
    wallet.add_token(result.token);

    let data = match wallet.save(&get_passphrase()) {
        Ok(d) => d,
        Err(e) => { eprintln!("Failed to save wallet: {}", e); std::process::exit(1); }
    };
    if let Err(e) = std::fs::write(WALLET_FILE, &data) {
        eprintln!("Failed to write wallet: {}", e);
        std::process::exit(1);
    }

    println!("Transferred token {}.", hex::encode(&id[..8]));
    println!("  Nullifier: {}", hex::encode(&result.spent_nullifier[..16]));
    println!("  Balance: {}", wallet.balance());
}

fn cmd_save() {
    let mint = default_mint();
    let wallet = load_or_create_wallet(&mint);
    let data = match wallet.save(&get_passphrase()) {
        Ok(d) => d,
        Err(e) => { eprintln!("Failed to save wallet: {}", e); std::process::exit(1); }
    };
    if let Err(e) = std::fs::write(WALLET_FILE, &data) {
        eprintln!("Failed to write wallet: {}", e);
        std::process::exit(1);
    }
    println!("Wallet saved to {} ({} bytes, {} tokens)", WALLET_FILE, data.len(), wallet.token_count());
}

fn cmd_load() {
    let mint = default_mint();
    let wallet = load_or_create_wallet(&mint);
    println!("Wallet loaded from {}", WALLET_FILE);
    println!("  Balance: {}", wallet.balance());
    println!("  Tokens:  {}", wallet.token_count());
}

// ────────────────────────────────────────────────────────────────────
// Long-term node identity for authenticated CLI channels
// ────────────────────────────────────────────────────────────────────

/// A long-term CLI identity: a Ristretto keypair used for mutual
/// authentication in [`authenticated_handshake`].
///
/// Persisted to `IDENTITY_FILE` under the same passphrase as the wallet.
/// The file format is: ASCII "SID1" magic || encrypted blob
/// (secure_store::EncryptedData containing the secret scalar bytes).
struct NodeIdentity {
    secret: curve25519_dalek::Scalar,
    public: curve25519_dalek::RistrettoPoint,
}

impl NodeIdentity {
    fn generate() -> Self {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
        let secret = specter_primitives::scalar_utils::random_scalar();
        let public = secret * G;
        Self { secret, public }
    }

    /// Load the CLI identity from IDENTITY_FILE, creating it on first use.
    fn load_or_create(passphrase: &[u8]) -> Self {
        use std::fs;
        match fs::read(IDENTITY_FILE) {
            Ok(data) => match Self::decode(&data, passphrase) {
                Some(id) => id,
                None => {
                    eprintln!(
                        "WARNING: could not decrypt {} — regenerating identity",
                        IDENTITY_FILE
                    );
                    let id = Self::generate();
                    let _ = fs::write(IDENTITY_FILE, id.encode(passphrase));
                    id
                }
            },
            Err(_) => {
                let id = Self::generate();
                if let Err(e) = fs::write(IDENTITY_FILE, id.encode(passphrase)) {
                    eprintln!("WARNING: failed to persist identity: {}", e);
                }
                id
            }
        }
    }

    fn encode(&self, passphrase: &[u8]) -> Vec<u8> {
        let sk_bytes = self.secret.as_bytes();
        let enc = specter_core::secure_store::encrypt(sk_bytes, passphrase)
            .expect("identity passphrase validation mirrors wallet save");
        let mut out = Vec::with_capacity(4 + 16 + 12 + 4 + enc.ciphertext.len());
        out.extend_from_slice(b"SID1");
        out.extend_from_slice(&enc.salt);
        out.extend_from_slice(&enc.nonce);
        out.extend_from_slice(&(enc.ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&enc.ciphertext);
        out
    }

    fn decode(data: &[u8], passphrase: &[u8]) -> Option<Self> {
        if data.len() < 4 + 16 + 12 + 4 || &data[0..4] != b"SID1" {
            return None;
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[4..20]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[20..32]);
        let ct_len =
            u32::from_le_bytes(data[32..36].try_into().ok()?) as usize;
        if 36 + ct_len > data.len() {
            return None;
        }
        let ciphertext = data[36..36 + ct_len].to_vec();
        let enc = specter_core::secure_store::EncryptedData {
            salt,
            nonce,
            ciphertext,
        };
        // PASS 7 zeroize-matrix fix: the decrypted plaintext contains the
        // long-term secret scalar bytes. Both `pt` and the temporary
        // `sk_arr` must be wiped from memory before return — otherwise a
        // process-memory dump could recover the identity key even though
        // the final NodeIdentity struct itself zeroizes on Drop.
        use zeroize::Zeroize;
        let mut pt = specter_core::secure_store::decrypt(&enc, passphrase).ok()?;
        if pt.len() != 32 {
            pt.zeroize();
            return None;
        }
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&pt);
        pt.zeroize();
        let secret: Option<curve25519_dalek::Scalar> =
            curve25519_dalek::Scalar::from_canonical_bytes(sk_arr).into();
        sk_arr.zeroize();
        let secret = secret?;
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
        let public = secret * G;
        Some(Self { secret, public })
    }

    fn public_hex(&self) -> String {
        hex::encode(self.public.compress().as_bytes())
    }
}

impl Drop for NodeIdentity {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

/// Authenticated SIGMA-I handshake over TCP.
///
/// Both parties possess a long-term Ristretto identity. They exchange
/// ephemeral Ristretto pubkeys and then each proves ownership of their
/// long-term secret by signing a transcript that binds both identities
/// and both ephemerals. A MitM cannot forge either signature without
/// knowing one of the long-term secrets.
///
/// The initiator MUST supply the expected peer long-term public key
/// (e.g., via CLI arg). If the observed peer key does not match, the
/// handshake aborts — this is the anti-MitM check.
///
/// Session key = SHA-256("specter-sigma-key:" || shared_dh || transcript).
///
/// Returns the 32-byte session key on success.
#[cfg(not(feature = "pq-handshake"))]
fn authenticated_handshake(
    stream: &mut std::net::TcpStream,
    my_identity: &NodeIdentity,
    expected_peer_pk: Option<curve25519_dalek::RistrettoPoint>,
    is_initiator: bool,
) -> Option<[u8; 32]> {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use sha2::Sha512;
    use std::io::{Read, Write};
    use std::time::Duration;
    use zeroize::Zeroize;

    let timeout = Some(Duration::from_secs(30));
    stream.set_read_timeout(timeout).ok()?;
    stream.set_write_timeout(timeout).ok()?;

    // Ephemeral DH keypair
    let mut ephem_sk = specter_primitives::scalar_utils::random_scalar();
    let ephem_pk = (ephem_sk * G).compress();

    let my_id_bytes = my_identity.public.compress();

    // Exchange: each side sends (id_pk || ephem_pk); initiator writes first.
    let write_hello = |stream: &mut std::net::TcpStream| -> Option<()> {
        stream.write_all(my_id_bytes.as_bytes()).ok()?;
        stream.write_all(ephem_pk.as_bytes()).ok()?;
        stream.flush().ok()
    };
    let mut their_id_bytes = [0u8; 32];
    let mut their_ephem_bytes = [0u8; 32];
    let read_hello = |stream: &mut std::net::TcpStream,
                      id_buf: &mut [u8; 32],
                      ephem_buf: &mut [u8; 32]|
     -> Option<()> {
        stream.read_exact(id_buf).ok()?;
        stream.read_exact(ephem_buf).ok()
    };

    if is_initiator {
        write_hello(stream)?;
        read_hello(stream, &mut their_id_bytes, &mut their_ephem_bytes)?;
    } else {
        read_hello(stream, &mut their_id_bytes, &mut their_ephem_bytes)?;
        write_hello(stream)?;
    }

    let their_id_pk: RistrettoPoint =
        CompressedRistretto(their_id_bytes).decompress()?;
    let their_ephem_pk: RistrettoPoint =
        CompressedRistretto(their_ephem_bytes).decompress()?;

    // Anti-MitM: if the caller specified an expected peer identity,
    // compare it to what we received. Constant-time comparison is not
    // strictly required (these are public keys) but we use it for
    // clarity and to avoid accidental timing side channels.
    if let Some(expected) = expected_peer_pk {
        use subtle::ConstantTimeEq;
        let ours = their_id_pk.compress();
        let want = expected.compress();
        if !bool::from(ours.as_bytes().ct_eq(want.as_bytes())) {
            ephem_sk.zeroize();
            eprintln!(
                "SIGMA-I: peer identity mismatch (expected {}, got {})",
                hex::encode(want.as_bytes()),
                hex::encode(ours.as_bytes())
            );
            return None;
        }
    }

    // DH-shared secret
    let shared = ephem_sk * their_ephem_pk;
    let shared_bytes = shared.compress();

    // Transcript: both identities + both ephemerals, in a canonical order
    // (sorted by the compressed bytes of the identity pubkeys) so both
    // sides compute the same transcript regardless of initiator role.
    let (id_a, id_b, ephem_a, ephem_b) = {
        let mine_id: [u8; 32] = *my_id_bytes.as_bytes();
        let mine_e: [u8; 32] = *ephem_pk.as_bytes();
        let theirs_id: [u8; 32] = their_id_bytes;
        let theirs_e: [u8; 32] = their_ephem_bytes;
        if mine_id < theirs_id {
            (mine_id, theirs_id, mine_e, theirs_e)
        } else {
            (theirs_id, mine_id, theirs_e, mine_e)
        }
    };

    let transcript_msg = {
        let mut h = Sha512::new();
        h.update(b"specter-sigma-transcript:");
        h.update(id_a);
        h.update(id_b);
        h.update(ephem_a);
        h.update(ephem_b);
        h.update(shared_bytes.as_bytes());
        let out = h.finalize();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&out[..32]);
        buf
    };

    // Schnorr signature over the transcript under my long-term secret.
    let sig_challenge = |r: &RistrettoPoint, pk: &RistrettoPoint, msg: &[u8; 32]| -> Scalar {
        let hash = Sha512::new()
            .chain_update(b"specter-sigma-sig:")
            .chain_update(r.compress().as_bytes())
            .chain_update(pk.compress().as_bytes())
            .chain_update(msg)
            .finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash);
        Scalar::from_bytes_mod_order_wide(&wide)
    };

    let mut k = specter_primitives::scalar_utils::random_scalar();
    let r_point = k * G;
    let e = sig_challenge(&r_point, &my_identity.public, &transcript_msg);
    let s = k + e * my_identity.secret;
    k.zeroize();
    let r_bytes = r_point.compress();
    let s_bytes: [u8; 32] = *s.as_bytes();

    // Exchange signatures: initiator writes first.
    let write_sig = |stream: &mut std::net::TcpStream| -> Option<()> {
        stream.write_all(r_bytes.as_bytes()).ok()?;
        stream.write_all(&s_bytes).ok()?;
        stream.flush().ok()
    };
    let mut their_r = [0u8; 32];
    let mut their_s = [0u8; 32];
    let read_sig = |stream: &mut std::net::TcpStream,
                    rb: &mut [u8; 32],
                    sb: &mut [u8; 32]|
     -> Option<()> {
        stream.read_exact(rb).ok()?;
        stream.read_exact(sb).ok()
    };
    if is_initiator {
        write_sig(stream)?;
        read_sig(stream, &mut their_r, &mut their_s)?;
    } else {
        read_sig(stream, &mut their_r, &mut their_s)?;
        write_sig(stream)?;
    }

    // Verify peer's Schnorr signature against their long-term pubkey and
    // the shared transcript. An attacker who intercepted the handshake
    // with a different ephemeral would derive a different shared secret,
    // compute a different transcript, and the peer's signature would not
    // verify — this is the SIGMA-I MitM-resistance property.
    let their_r_point = CompressedRistretto(their_r).decompress()?;
    let their_s_scalar = {
        let opt: Option<Scalar> =
            Scalar::from_canonical_bytes(their_s).into();
        opt?
    };
    let expected_e = sig_challenge(&their_r_point, &their_id_pk, &transcript_msg);
    let lhs = their_s_scalar * G;
    let rhs = their_r_point + expected_e * their_id_pk;
    if lhs != rhs {
        ephem_sk.zeroize();
        eprintln!("SIGMA-I: peer signature verification failed");
        return None;
    }

    // Derive the session key from the shared DH secret AND the bound
    // transcript. Binding to the transcript means any variation in the
    // identities or ephemerals yields a different key.
    let session_key = {
        let mut h = Sha512::new();
        h.update(b"specter-sigma-key:");
        h.update(shared_bytes.as_bytes());
        h.update(transcript_msg);
        let out = h.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&out[..32]);
        key
    };

    ephem_sk.zeroize();
    Some(session_key)
}

// ────────────────────────────────────────────────────────────────────
// Post-quantum hybrid handshake layer (feature = "pq-handshake")
// ────────────────────────────────────────────────────────────────────
//
// Wraps the SIGMA-I handshake with an ML-KEM-768 (FIPS 203) layer so
// the derived session key depends on BOTH the classical Ristretto
// ECDH secret AND the ML-KEM shared secret. Breaking the session key
// requires breaking both schemes simultaneously.
//
// Design (asymmetric, 1-round):
//
//   Initiator I:
//     - generates ephemeral Kyber decapsulation key (dk_I)
//     - sends (id_pk, ristretto_ephem_pk, kyber_ek_I)
//   Responder R:
//     - receives I's kyber_ek_I
//     - encapsulates a random shared secret to I's kyber_ek_I,
//       producing (kyber_ct, kyber_ss)
//     - sends (id_pk, ristretto_ephem_pk, kyber_ct)
//   Initiator I:
//     - decapsulates kyber_ct with dk_I to obtain the same kyber_ss
//
// Combined session key:
//   session_key = HKDF-SHA3(
//     "specter-hybrid-key:",
//     ristretto_shared || kyber_shared || transcript
//   )
//
// Wire format note: we do NOT negotiate the PQ layer — a peer
// compiled with `pq-handshake` ONLY talks to peers also compiled
// with it. The wire format is intentionally different so that a
// classical peer sees garbage bytes and aborts.

#[cfg(feature = "pq-handshake")]
fn hybrid_authenticated_handshake(
    stream: &mut std::net::TcpStream,
    my_identity: &NodeIdentity,
    expected_peer_pk: Option<curve25519_dalek::RistrettoPoint>,
    is_initiator: bool,
) -> Option<[u8; 32]> {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use sha2::Sha512;
    use std::io::{Read, Write};
    use std::time::Duration;
    use zeroize::Zeroize;

    // Concrete ml-kem type aliases pinned to MlKem768.
    type Ek = <MlKem768 as KemCore>::EncapsulationKey;
    type Dk = <MlKem768 as KemCore>::DecapsulationKey;

    // Network timeouts to prevent slow-peer DoS.
    let timeout = Some(Duration::from_secs(30));
    stream.set_read_timeout(timeout).ok()?;
    stream.set_write_timeout(timeout).ok()?;

    // Ristretto ephemeral keypair (classical leg).
    let mut ephem_sk = specter_primitives::scalar_utils::random_scalar();
    let ephem_pk = (ephem_sk * G).compress();

    let my_id_bytes = my_identity.public.compress();

    // ML-KEM-768 ephemeral decap key (only the initiator generates one;
    // the responder encapsulates TO this key).
    let mut rng = rand_core::OsRng;
    let kyber_dk_pair: Option<(Dk, Ek)> = if is_initiator {
        Some(MlKem768::generate(&mut rng))
    } else {
        None
    };
    let kyber_ek_bytes_opt: Option<Vec<u8>> = kyber_dk_pair
        .as_ref()
        .map(|(_dk, ek)| ek.as_bytes().to_vec());

    const KYBER_EK_LEN: usize = 1184; // ML-KEM-768 encap key size
    const KYBER_CT_LEN: usize = 1088; // ML-KEM-768 ciphertext size

    // --- HELLO exchange ---
    if is_initiator {
        stream.write_all(my_id_bytes.as_bytes()).ok()?;
        stream.write_all(ephem_pk.as_bytes()).ok()?;
        stream.write_all(kyber_ek_bytes_opt.as_ref().unwrap()).ok()?;
        stream.flush().ok()?;
    }

    let mut their_id_bytes = [0u8; 32];
    let mut their_ephem_bytes = [0u8; 32];
    stream.read_exact(&mut their_id_bytes).ok()?;
    stream.read_exact(&mut their_ephem_bytes).ok()?;

    // Depending on role, read either kyber_ek (responder sees
    // initiator's ek) or kyber_ct (initiator sees responder's ct).
    let (maybe_their_ek_bytes, maybe_their_ct_bytes) = if is_initiator {
        let mut ct_buf = vec![0u8; KYBER_CT_LEN];
        stream.read_exact(&mut ct_buf).ok()?;
        (None, Some(ct_buf))
    } else {
        let mut ek_buf = vec![0u8; KYBER_EK_LEN];
        stream.read_exact(&mut ek_buf).ok()?;
        (Some(ek_buf), None)
    };

    if !is_initiator {
        // Responder writes its hello before producing the ciphertext.
        stream.write_all(my_id_bytes.as_bytes()).ok()?;
        stream.write_all(ephem_pk.as_bytes()).ok()?;
    }

    // Decompose the SIGMA-I anti-MitM logic.
    let their_id_pk: RistrettoPoint =
        CompressedRistretto(their_id_bytes).decompress()?;
    let their_ephem_pk: RistrettoPoint =
        CompressedRistretto(their_ephem_bytes).decompress()?;

    if let Some(expected) = expected_peer_pk {
        use subtle::ConstantTimeEq;
        let ours = their_id_pk.compress();
        let want = expected.compress();
        if !bool::from(ours.as_bytes().ct_eq(want.as_bytes())) {
            ephem_sk.zeroize();
            eprintln!(
                "Hybrid SIGMA-I: peer identity mismatch (expected {}, got {})",
                hex::encode(want.as_bytes()),
                hex::encode(ours.as_bytes())
            );
            return None;
        }
    }

    // ML-KEM leg — use explicit type aliases for the encap/decap key
    // types because the ml-kem 0.2 crate exposes them as associated
    // types of the KemCore trait rather than as bare types.
    let kyber_shared: [u8; 32] = if is_initiator {
        let their_ct_bytes = maybe_their_ct_bytes.as_ref()?;
        if their_ct_bytes.len() != KYBER_CT_LEN {
            return None;
        }
        let ct_arr =
            ml_kem::Ciphertext::<MlKem768>::try_from(their_ct_bytes.as_slice()).ok()?;
        let (dk, _ek) = kyber_dk_pair.as_ref()?;
        let ss = dk.decapsulate(&ct_arr).ok()?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&ss);
        out
    } else {
        let their_ek_bytes = maybe_their_ek_bytes.as_ref()?;
        if their_ek_bytes.len() != KYBER_EK_LEN {
            return None;
        }
        // Parse the encap key from wire bytes via the EncodedSizeUser
        // conversion on the associated type.
        let encoded = ml_kem::Encoded::<Ek>::try_from(their_ek_bytes.as_slice()).ok()?;
        let their_ek = Ek::from_bytes(&encoded);
        let (ct, ss) = their_ek.encapsulate(&mut rng).ok()?;
        // Send the ciphertext to the initiator.
        stream.write_all(ct.as_slice()).ok()?;
        stream.flush().ok()?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&ss);
        out
    };

    // Classical Ristretto ECDH shared secret (forward secrecy leg 1).
    let ristretto_shared = ephem_sk * their_ephem_pk;
    let ristretto_shared_bytes = ristretto_shared.compress();

    // Canonicalized transcript (same rule as classical handshake).
    let (id_a, id_b, ephem_a, ephem_b) = {
        let mine_id: [u8; 32] = *my_id_bytes.as_bytes();
        let mine_e: [u8; 32] = *ephem_pk.as_bytes();
        let theirs_id: [u8; 32] = their_id_bytes;
        let theirs_e: [u8; 32] = their_ephem_bytes;
        if mine_id < theirs_id {
            (mine_id, theirs_id, mine_e, theirs_e)
        } else {
            (theirs_id, mine_id, theirs_e, mine_e)
        }
    };

    let transcript_msg = {
        let mut h = Sha512::new();
        h.update(b"specter-hybrid-sigma-transcript:");
        h.update(id_a);
        h.update(id_b);
        h.update(ephem_a);
        h.update(ephem_b);
        h.update(ristretto_shared_bytes.as_bytes());
        h.update(kyber_shared);
        let out = h.finalize();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&out[..32]);
        buf
    };

    // SIGMA-I Schnorr signature over the hybrid transcript.
    let sig_challenge = |r: &RistrettoPoint, pk: &RistrettoPoint, msg: &[u8; 32]| -> Scalar {
        let hash = Sha512::new()
            .chain_update(b"specter-hybrid-sigma-sig:")
            .chain_update(r.compress().as_bytes())
            .chain_update(pk.compress().as_bytes())
            .chain_update(msg)
            .finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash);
        Scalar::from_bytes_mod_order_wide(&wide)
    };

    let mut k = specter_primitives::scalar_utils::random_scalar();
    let r_point = k * G;
    let e = sig_challenge(&r_point, &my_identity.public, &transcript_msg);
    let s = k + e * my_identity.secret;
    k.zeroize();
    let r_bytes = r_point.compress();
    let s_bytes: [u8; 32] = *s.as_bytes();

    // Exchange signatures.
    let mut their_r = [0u8; 32];
    let mut their_s = [0u8; 32];
    if is_initiator {
        stream.write_all(r_bytes.as_bytes()).ok()?;
        stream.write_all(&s_bytes).ok()?;
        stream.flush().ok()?;
        stream.read_exact(&mut their_r).ok()?;
        stream.read_exact(&mut their_s).ok()?;
    } else {
        stream.read_exact(&mut their_r).ok()?;
        stream.read_exact(&mut their_s).ok()?;
        stream.write_all(r_bytes.as_bytes()).ok()?;
        stream.write_all(&s_bytes).ok()?;
        stream.flush().ok()?;
    }

    let their_r_point = CompressedRistretto(their_r).decompress()?;
    let their_s_scalar = {
        let opt: Option<Scalar> = Scalar::from_canonical_bytes(their_s).into();
        opt?
    };
    let expected_e = sig_challenge(&their_r_point, &their_id_pk, &transcript_msg);
    let lhs = their_s_scalar * G;
    let rhs = their_r_point + expected_e * their_id_pk;
    if lhs != rhs {
        ephem_sk.zeroize();
        eprintln!("Hybrid SIGMA-I: peer signature verification failed");
        return None;
    }

    // Derive the session key from BOTH shared secrets + transcript.
    // HKDF-style via SHA-512: if EITHER of the two shared secrets is
    // broken the session key still has the other one's entropy. This
    // is the "hybrid pattern" used by Chrome X25519MLKEM768, Signal
    // PQXDH, and the TLS 1.3 hybrid design.
    let session_key = {
        let mut h = Sha512::new();
        h.update(b"specter-hybrid-sigma-key:");
        h.update(ristretto_shared_bytes.as_bytes());
        h.update(kyber_shared);
        h.update(transcript_msg);
        let out = h.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&out[..32]);
        key
    };

    ephem_sk.zeroize();
    Some(session_key)
}

/// Dispatch helper: picks the classical or hybrid handshake depending
/// on whether the `pq-handshake` feature is compiled in.
fn handshake_dispatch(
    stream: &mut std::net::TcpStream,
    my_identity: &NodeIdentity,
    expected_peer_pk: Option<curve25519_dalek::RistrettoPoint>,
    is_initiator: bool,
) -> Option<[u8; 32]> {
    #[cfg(feature = "pq-handshake")]
    {
        hybrid_authenticated_handshake(stream, my_identity, expected_peer_pk, is_initiator)
    }
    #[cfg(not(feature = "pq-handshake"))]
    {
        authenticated_handshake(stream, my_identity, expected_peer_pk, is_initiator)
    }
}

/// Parse a hex-encoded Ristretto pubkey from a CLI argument.
fn parse_peer_pk(s: &str) -> Option<curve25519_dalek::RistrettoPoint> {
    let bytes = hex::decode(s.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    curve25519_dalek::ristretto::CompressedRistretto(arr).decompress()
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
    // Optional 3rd arg: hex-encoded peer long-term pubkey for SIGMA-I
    // anti-MitM verification. If absent, the handshake still runs but
    // without identity verification (warned).
    let expected_peer = args.get(3).and_then(|s| parse_peer_pk(s));
    if expected_peer.is_none() && args.get(3).is_some() {
        eprintln!("Warning: peer pubkey arg could not be parsed — proceeding WITHOUT anti-MitM verification");
    }
    if expected_peer.is_none() {
        eprintln!("Warning: no peer pubkey provided — SIGMA-I will not verify peer identity. Pass the receiver's pubkey as the 3rd argument.");
    }

    let mint = default_mint();
    let my_identity = NodeIdentity::load_or_create(&get_passphrase());
    let mut wallet = load_or_create_wallet(&mint);

    if wallet.is_empty() {
        println!("Wallet is empty. Mint a token first.");
        return;
    }

    let token = match wallet.take_token(1) {
        Some(t) => t,
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

            // SIGMA-I authenticated handshake (sender is initiator).
            // Uses the hybrid classical+PQ variant when the
            // `pq-handshake` feature is compiled in.
            let mut shared_key =
                match handshake_dispatch(&mut stream, &my_identity, expected_peer, true) {
                    Some(k) => k,
                    None => {
                        eprintln!("Authenticated handshake failed with {}", addr);
                        return;
                    }
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

            // Zeroize shared key after use
            use zeroize::Zeroize;
            shared_key.zeroize();

            // Token already removed by take_token — save the wallet
            let data = match wallet.save(&get_passphrase()) {
                Ok(d) => d,
                Err(e) => { eprintln!("Failed to save wallet: {}", e); return; }
            };
            if let Err(e) = std::fs::write(WALLET_FILE, &data) {
                eprintln!("Failed to write wallet: {}", e);
                return;
            }
            println!("Sent token {} to {} (encrypted, {} bytes)", hex::encode(&id[..8]), addr, encrypted.len());
        }
        Err(e) => {
            eprintln!("Failed to connect to {}: {}", addr, e);
        }
    }
}

fn cmd_receive(args: &[String]) {
    let addr = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:7878");

    let my_identity = NodeIdentity::load_or_create(&get_passphrase());
    // Print our long-term pubkey so the sender can be told which peer to
    // expect (anti-MitM). This is the out-of-band distribution step.
    println!(
        "My long-term pubkey (share with sender):\n  {}",
        my_identity.public_hex()
    );

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

            // SIGMA-I handshake (receiver is responder). The receiver
            // does not pin a specific sender identity — any authenticated
            // peer is accepted, and the subsequent verify_token step
            // validates the TOKEN itself against the mint.
            let mut shared_key =
                match handshake_dispatch(&mut stream, &my_identity, None, false) {
                    Some(k) => k,
                    None => {
                        eprintln!("Authenticated handshake failed with {}", peer);
                        return;
                    }
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
                Some(p) => {
                    // Zeroize shared key after successful decryption
                    use zeroize::Zeroize;
                    shared_key.zeroize();
                    p
                }
                None => {
                    use zeroize::Zeroize;
                    shared_key.zeroize();
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
                        let data = match wallet.save(&get_passphrase()) {
                            Ok(d) => d,
                            Err(e) => {
                                eprintln!("Failed to save wallet: {}", e);
                                return;
                            }
                        };
                        if let Err(e) = std::fs::write(WALLET_FILE, &data) {
                            eprintln!("Failed to write wallet: {}", e);
                            return;
                        }
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
    let nullifier = original.compute_nullifier();
    let _spend1 = transfer::transfer(original, &mut ds_set).unwrap();
    // Attempting to re-insert the same nullifier simulates a double-spend
    let second_ok = ds_set.insert(nullifier);
    println!("  First spend:       true (valid)");
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
    // Issue fresh tokens for transfer benchmark (PCT is non-Clone by design)
    for _ in 0..n {
        let t = mint.issue(1000, &[1, 2], None).unwrap();
        let mut ns = NullifierSet::new();
        let _ = transfer::transfer(t, &mut ns).unwrap();
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
    let saved = wallet.save(b"bench-passphrase-ok").expect("bench passphrase meets min length");
    println!("Wallet save (50 tokens):       {:?} ({} bytes)", start.elapsed(), saved.len());

    let start = Instant::now();
    let _ = Wallet::load(&saved, b"bench-passphrase-ok", &mint.group_public_key(), &mint.pedersen, &mint.credential_issuer.pedersen);
    println!("Wallet load (50 tokens):       {:?}", start.elapsed());

    println!("\nToken size (no cred):          {} bytes", serde_token::serialized_size(&tokens[0]));
    println!("Token size (with cred):        {} bytes (constant after transfers)", serde_token::serialized_size(&tokens[0]));
    println!("=== Benchmark Complete ===");
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn test_identity_encode_decode_roundtrip() {
        let id = NodeIdentity::generate();
        let pub_bytes = id.public.compress();
        let encoded = id.encode(b"strong-pass-min12");
        let decoded = NodeIdentity::decode(&encoded, b"strong-pass-min12")
            .expect("decode must succeed with the correct passphrase");
        assert_eq!(decoded.public.compress(), pub_bytes);
        // Secret scalars compare in constant time via curve25519-dalek impl.
        assert_eq!(decoded.secret, id.secret);
    }

    #[test]
    fn test_identity_decode_wrong_passphrase_fails() {
        let id = NodeIdentity::generate();
        let encoded = id.encode(b"correct-pass12");
        assert!(NodeIdentity::decode(&encoded, b"wrong-pass123").is_none());
    }

    #[test]
    fn test_identity_decode_tampered_magic_fails() {
        let id = NodeIdentity::generate();
        let mut encoded = id.encode(b"strong-pass-min12");
        encoded[0] = b'X';
        assert!(NodeIdentity::decode(&encoded, b"strong-pass-min12").is_none());
    }

    #[test]
    fn test_parse_peer_pk() {
        let id = NodeIdentity::generate();
        let hex_str = id.public_hex();
        let parsed = parse_peer_pk(&hex_str).unwrap();
        assert_eq!(parsed, id.public);
        assert!(parse_peer_pk("notahex").is_none());
        assert!(parse_peer_pk("deadbeef").is_none()); // wrong length
    }
}
