//! Fuzz deserialization of SbtRequest — the wire type sent from
//! client to mint. Must not panic on any input.

#![no_main]
use libfuzzer_sys::fuzz_target;
use specter_sbt::scheme::SbtRequest;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = bincode::deserialize::<SbtRequest>(data) {
        let _ = req.validate();
    }
});
