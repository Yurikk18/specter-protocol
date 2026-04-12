//! Fuzz the deserialization + validation path of SpendToken.
//!
//! The goal is to ensure that no maliciously crafted byte sequence
//! can cause a panic, stack overflow, or OOM during serde
//! deserialization or the subsequent `validate()` / `nullifier()`
//! call chain. Any error return is fine; only panics are bugs.

#![no_main]
use libfuzzer_sys::fuzz_target;
use specter_sbt::scheme::SpendToken;

fuzz_target!(|data: &[u8]| {
    if let Ok(token) = bincode::deserialize::<SpendToken>(data) {
        let _ = token.validate();
        let _ = token.nullifier();
    }
});
