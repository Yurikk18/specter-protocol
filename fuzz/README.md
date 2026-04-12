# specter-fuzz

Fuzz harnesses for the Specter Protocol attack surfaces flagged by the
purple-team audit. Each target wraps a public parsing or crypto entry
point that accepts untrusted bytes.

## Targets

| name                         | attack surface                                |
| ---------------------------- | --------------------------------------------- |
| `fuzz_deserialize_token`     | PCT wire format parser + round-trip stability |
| `fuzz_ristretto_decompress`  | `CompressedRistretto::decompress` panics      |
| `fuzz_wallet_decrypt`        | ChaCha20-Poly1305 AEAD tag verification path  |
| `fuzz_nullifier_insert`      | HashSet invariants under adversarial input    |
| `fuzz_verify_presentation`   | anonymous credential presentation verifier    |
| `fuzz_sbt_spend_token`       | SBT SpendToken bincode deser + validate + nullifier |
| `fuzz_sbt_request`           | SBT SbtRequest bincode deser + validate       |
| `fuzz_sbt_evaluation`        | SBT OprfEvaluation bincode deser + validate   |

## Running

Requires nightly Rust and `cargo-fuzz` (uses libFuzzer):

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run fuzz_deserialize_token
cargo +nightly fuzz run fuzz_ristretto_decompress
cargo +nightly fuzz run fuzz_wallet_decrypt
cargo +nightly fuzz run fuzz_nullifier_insert
cargo +nightly fuzz run fuzz_verify_presentation
cargo +nightly fuzz run fuzz_sbt_spend_token
cargo +nightly fuzz run fuzz_sbt_request
cargo +nightly fuzz run fuzz_sbt_evaluation
```

libFuzzer is not supported on Windows — run these on Linux or macOS in CI.

## Invariants each target enforces

- **never panics** on arbitrary input (DoS surface)
- **never produces an undefined point** (unsoundness surface)
- **never diverges from a reference set** (for nullifier target)
- **idempotent round-trip** (serialize → parse → serialize for deserialize_token)

Any crash reported by libFuzzer counts as a CRITICAL finding and must be
patched before shipping.
