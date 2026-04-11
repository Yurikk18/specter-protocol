//! Fuzz target: NullifierSet random insertion uniqueness.
//!
//! Slices the fuzz input into 32-byte nullifiers and inserts them all
//! into a NullifierSet. Asserts two invariants:
//!   1. The second insert of any nullifier always returns false.
//!   2. `len()` equals the number of *distinct* 32-byte slices observed.
//!
//! This exercises the nullifier set's atomic check-and-insert guarantee
//! against adversarial input streams that stress the HashSet's internal
//! invariants and stability.

#![no_main]

use libfuzzer_sys::fuzz_target;
use specter_core::nullifier::NullifierSet;
use std::collections::HashSet;

fuzz_target!(|data: &[u8]| {
    let mut set = NullifierSet::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();

    for chunk in data.chunks_exact(32) {
        let mut n = [0u8; 32];
        n.copy_from_slice(chunk);
        let first_time = seen.insert(n);
        let inserted = set.insert(n);
        assert_eq!(
            first_time, inserted,
            "NullifierSet insert must return true iff nullifier is new"
        );
    }

    assert_eq!(set.len(), seen.len(), "nullifier set len diverged");
});
