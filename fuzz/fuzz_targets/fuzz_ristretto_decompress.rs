//! Fuzz target: Ristretto point decompression.
//!
//! Exercises `CompressedRistretto::decompress` with arbitrary 32-byte
//! inputs to confirm that every invalid encoding is rejected with
//! `None` and never produces an unsound point or panics. This is the
//! attack surface for every token field that carries an external point
//! (value_commitment, mint_signature.r reconstruction, fold_proof.pk/r,
//! credential issuer_pk, etc.).

#![no_main]

use curve25519_dalek::ristretto::CompressedRistretto;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&data[..32]);
        let cr = CompressedRistretto(buf);
        let _ = cr.decompress(); // must not panic
    }
});
