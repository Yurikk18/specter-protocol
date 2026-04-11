//! Fuzz target: selective-disclosure presentation parsing.
//!
//! Replays bytes into deserialize_token. If a credential presentation
//! parses successfully we run `verify_presentation` to confirm the
//! verifier never panics on arbitrary internal state. This is the
//! credential-layer equivalent of fuzz_deserialize_token.

#![no_main]

use libfuzzer_sys::fuzz_target;
use specter_core::serde_token;
use specter_credential::presentation;
use specter_primitives::pedersen::PedersenParams;

fuzz_target!(|data: &[u8]| {
    if let Ok(tok) = serde_token::deserialize_token(data) {
        if let Some(pres) = tok.presentation.as_ref() {
            let pedersen = PedersenParams::new();
            // Must not panic regardless of structural validity. We don't
            // assert truthiness — the result can be either bool.
            let _ = presentation::verify_presentation(pres, &pedersen);
        }
    }
});
