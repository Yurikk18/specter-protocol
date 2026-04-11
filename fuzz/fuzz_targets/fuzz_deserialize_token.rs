//! Fuzz target: PCT wire-format deserializer.
//!
//! Feeds arbitrary bytes to `serde_token::deserialize_token` and asserts
//! the function never panics, unwinds, or over-allocates. Any panic is
//! a security bug (denial-of-service vector on any endpoint that parses
//! tokens from the network or disk).
//!
//! If the parse succeeds we also re-serialize and compare lengths as a
//! round-trip smoke check.

#![no_main]

use libfuzzer_sys::fuzz_target;
use specter_core::serde_token;

fuzz_target!(|data: &[u8]| {
    if let Ok(tok) = serde_token::deserialize_token(data) {
        // Round-trip: re-serialize must succeed and produce a stable size.
        let bytes = serde_token::serialize_token(&tok);
        // Size may differ from the input (trailing bytes dropped) but the
        // re-serialization must itself be idempotent.
        let again = serde_token::deserialize_token(&bytes)
            .expect("re-deserialization of self-produced bytes must succeed");
        let bytes2 = serde_token::serialize_token(&again);
        assert_eq!(bytes, bytes2, "serialize is not idempotent on valid input");
    }
});
