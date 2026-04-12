# Contributing to Specter Protocol

## Getting Started

```bash
git clone <repo-url>
cd phantasm
cargo build --workspace
cargo test --workspace
```

Requires Rust stable toolchain (`stable-x86_64-pc-windows-msvc` on Windows, `stable` on Linux/macOS).

## Crate Structure

| Crate | Purpose | Key Types |
|-------|---------|-----------|
| `specter-primitives` | Pedersen commitments, Shamir sharing, scalar utils | `PedersenParams`, `Share` |
| `specter-blind-sig` | Blind signatures (standard + clause + threshold + DKG) | `SignerKeypair`, `BlindSignature`, `ThresholdKeyset` |
| `specter-fold` | Proof accumulation, Fiat-Shamir transcripts | `AccumulatedProof`, `Transcript` |
| `specter-credential` | Anonymous credentials, selective disclosure, revocation | `Credential`, `Presentation`, `Issuer` |
| `specter-core` | PCT lifecycle (mint, transfer, verify, wallet, nullifiers) | `ProofCarryingToken`, `Mint`, `Wallet`, `NullifierSet` |
| `specter-offline` | VDF time-locks, reputation bonds | `VdfProof`, `RsaVdfProof`, `BondRegistry` |
| `specter-net` | BFT consensus, gossip, attestation chains | `ConsensusState`, `GossipProtocol`, `AttestationChain` |
| `specter-cli` | CLI binary (demo, benchmarks, wallet, hybrid PQ handshake) | — |
| `specter-tee` | AMD SEV-SNP attestation, TCB policy, portable verify | `AttestationProvider`, `PortableSnpVerifier`, `TcbPolicy` |
| `specter-sbt` | Symmetric Blind Tokens (threshold DH-OPRF + Chaum-Pedersen NIZK) | `SbtScheme`, `SpendToken`, `OprfEvaluation`, `SbtNullifier` |

## Security Rules

These rules are mandatory for all contributions:

### Secret Handling

1. **Every type holding secret scalars, keys, or blinding factors must implement `Drop` with `zeroize`**. See `Share`, `Credential`, `ValidatorKey` for examples.
2. **Custom `Debug` that redacts secrets**. Never use `#[derive(Debug)]` on types with secret fields. Print `[REDACTED]` instead.
3. **No `Clone` on bearer instruments or signing keys**. `ProofCarryingToken` and `ValidatorKey` are deliberately non-Clone. `Credential` and `ThresholdKeyset` retain Clone because cross-crate serialization requires it, but they implement Drop+zeroize.

### Cryptographic Operations

4. **Use `specter_primitives::scalar_utils`** for scalar creation. Never call `Scalar::from_bytes_mod_order` directly outside the primitives crate.
5. **Use `random_scalar()`** for all cryptographic randomness. It uses `OsRng` (CSPRNG) internally.
6. **Domain-separate everything**. Every hash, transcript, and signature challenge must include a unique `b"specter-..."` prefix.
7. **Length-prefix variable data** in hash inputs to prevent concatenation ambiguity.
8. **Use `checked_add`/`checked_mul`** for security-critical arithmetic (transfer counts, values, step counters).

### Error Handling

9. **Return `Result`, never `panic!`** in library code for conditions triggered by external input. The `encrypt()` function in secure_store is the reference pattern.
10. **Validate inputs at trust boundaries** (deserialization, network receive, file load). See `deserialize_token()` for validation patterns.

### Testing

11. **Test passphrases must be >= 8 bytes** (e.g., `b"pass-min8"`).
12. **Double-spend tests** use `token.compute_nullifier()` + `ns.insert()` — never clone a `ProofCarryingToken` for testing double-spend.
13. **Use `Wallet::take_token()`** instead of `select_token().clone()` to get tokens for transfer.

## Adding a New Attribute to Credentials

The credential system uses a 5-attribute Pedersen vector commitment. To add attribute #6:

1. Add the field to `Attributes` in `specter-credential/src/credential.rs`
2. Add its scalar encoding to `Attributes::to_scalars()`
3. Update `Attributes::count()` to return 6
4. Add `ATTR_NEW_NAME: usize = 5` constant in `presentation.rs`
5. Update `serde_token.rs` serialization/deserialization
6. Update all tests that construct `Attributes`

## Running Nova IVC Tests

Nova IVC requires Linux or macOS (pasta-msm assembly is incompatible with Windows linkers):

```bash
cargo test -p specter-fold --features nova -- --include-ignored
```

## Code Style

- `cargo fmt --all` before committing
- `cargo clippy --workspace` should be clean
- No unnecessary `pub` on secret fields
- Comments explaining **why**, not **what**
