//! Fuzz deserialization of OprfEvaluation — the wire type sent from
//! each trustee to the client. Must not panic on any input.

#![no_main]
use libfuzzer_sys::fuzz_target;
use specter_sbt::oprf::OprfEvaluation;

fuzz_target!(|data: &[u8]| {
    if let Ok(eval) = bincode::deserialize::<OprfEvaluation>(data) {
        let _ = eval.validate();
    }
});
