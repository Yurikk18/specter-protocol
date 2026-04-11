//! Fuzz target: wallet ciphertext decryption + parse.
//!
//! A malicious or corrupted wallet file must never panic. This target
//! feeds arbitrary bytes directly into the wallet parser path (not the
//! Argon2 KDF, which is too slow for fuzzing) by constructing an
//! EncryptedData envelope and passing it through `decrypt`. The fuzzer
//! is expected to hit every error branch of the ChaCha20-Poly1305 tag
//! check and the subsequent token-parse path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use specter_core::secure_store::{decrypt, EncryptedData};

// Fixed passphrase so the Argon2 KDF result is deterministic. The KDF
// still runs once per input but the fuzzer's iteration rate is dominated
// by the parse logic we care about, not the KDF itself.
const PASS: &[u8] = b"fuzz-pass-min12";

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[..16]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[16..28]);
    let ct = data[28..].to_vec();
    let ed = EncryptedData {
        salt,
        nonce,
        ciphertext: ct,
    };
    let _ = decrypt(&ed, PASS); // must not panic on any input
});
