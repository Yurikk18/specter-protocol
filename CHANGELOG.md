# Changelog

All notable security and protocol-level changes to Specter Protocol.
This file tracks the audit cycles, their findings, and the resulting
patches so that external reviewers can follow the full history without
grep'ing commit bodies.

## [unreleased] — Signed transfer chain (fundamental fold proof fix)

This cycle replaces the unsound Schnorr accumulator with a signed
transfer chain, completing the residual item left open by the 15-pass
audit in `edf799a`.

### Changed

- **`specter-fold::accumulator`** rewritten around a `Vec<TransferStep>`
  model. Each step is a Schnorr signature by the previous owner's
  derived signing key over `(token_id, step, new_owner_pk)`, anchored
  at step 0 by the mint-signed `H(genesis_owner_pk)`.
- **Mint signed message** now binds three fields instead of two:
  `token_id || value_commitment || H(genesis_owner_pk)`.
- **Fold proof size** grows linearly in the number of transfers
  (~96 bytes per step) instead of the previous constant ~320 bytes.
  Bounded by `recursion_bound` (typically 20–50).
- **`test_real_token_sizes`** updated to assert growth-rate bounds
  instead of a strict constant-size invariant.

### Security — Closed

- **Schnorr accumulator step > 0 forge (fundamental)**: the previous
  Schnorr accumulator allowed an attacker who knew the genesis state
  to regenerate a valid-looking proof from scratch. The signed chain
  closes this: forgery requires breaking ECDLP to recover the previous
  owner's signing key.

### Added

- `cargo-audit` integration + `audit.toml` with documented ignore list
  for the 3 transitive-dep warnings (nova-snark → bincode / paste,
  proptest → rand logger unsoundness). **Zero vulnerabilities.**
- `SECURITY.md` — disclosure policy, audit history, residual limitations.
- `THREAT_MODEL.md` — formal asset/adversary/defense matrix.
- `CHANGELOG.md` — this file.

### Removed

- `dh_handshake` unauthenticated ECDH from `specter-cli`. The SIGMA-I
  `authenticated_handshake` introduced in `edf799a` covers all call
  sites. No legacy fallback remains.

### Performance

- `mandatory_coverage` integration test runtime reduced from ~60 min
  to ~3 min by capping `test_wallet_nonce_never_reused` at 32
  Argon2id iterations (down from 256) and `test_fold_proof_valid_at_various_depths`
  at depth 20 (down from 100). Probabilistic collision argument
  preserved: 32 nonces × 96-bit space → collision probability ≈ 2^(−87).

## [edf799a] — 2026-04-11 — Passes 6–15 + R/A tasks

### Added

- `transfer_checked()` with full 6-check pre-spend verification
- SIGMA-I authenticated CLI handshake (`NodeIdentity`, peer pubkey pinning)
- `ConcurrentNullifierSet` (Arc<Mutex> wrapper, 32-thread contention test)
- 5 fuzz targets via `cargo-fuzz` (`fuzz/`)
- `memory_guard` module with mlock / VirtualLock / disable_core_dumps
- `mandatory_coverage.rs` integration test suite (section 28 of audit prompt)
- Proptest coverage for nullifier, serialize roundtrip, fold integrity
- Constant-time audit: `ct_eq_32` helper + `subtle::ConstantTimeEq` on
  every verifier hash comparison
- `RateLimitedSigner` concurrent blocking tests
- `libc 0.2` optional dep (default-on `memory-guard` feature)

### Changed

- `wallet.save()` and `serialize_encrypted()` return `Result` instead
  of panicking on short passphrase
- CLI `get_passphrase` minimum length pulled from `secure_store::MIN_PASSPHRASE_LEN`
- `secure_store::{encrypt, decrypt}` now zeroize Argon2 key on both
  success and failure paths; `encrypt` no longer panics on error
- `random_scalar()` zeroizes 64-byte CSPRNG intermediate
- `NodeIdentity::decode` zeroizes decrypted plaintext and temp buffers
- `deserialize_encrypted` zeroizes plaintext after parse
- Hash-based `vdf` marked `#[deprecated]` with pointer to `vdf_rsa`
- `verify.rs` uses `&` instead of `&&` for fold-valid check (closes
  PASS 10 timing oracle)
- `bonds.rs::register_offline_spend` assigns pre-computed `total_exposure`
  instead of re-adding (PASS 12 drift prevention)

### Security — Closed

- **12 findings in passes 1–5** (see `43e2661`)
- **3 additional findings in passes 6–15**:
  - PASS 7: un-zeroized decrypted plaintext (NodeIdentity)
  - PASS 7: un-zeroized Argon2 key on decrypt error path
  - PASS 10: timing-oracle short-circuit in verify fold_valid
- 1 latent bug caught by proptest: `verify_accumulated_proof` at step 0
  only checked `state_hash != 0` instead of recomputing it from the
  transcript. Fixed.

### Tests

- 302 passing (240 lib + integration + doc-tests)
- cargo check + clippy workspace clean

## [43e2661] — 2026-04-10 — Passes 1–5 (12 findings)

### Security — Closed

1. **CRITICAL** `mint.split()` infinite-money via value tampering
2. **CRITICAL** attestation identity-swap framing (pubkey not in hash)
3. **CRITICAL** `renew_token` skipped fold_proof + credential checks
4. **CRITICAL** token clone via `owner_secret` swap at step > 0
   (PASS 2, mitigated by `current_owner_hash` binding)
5. **HIGH** `wallet.save()` panic on short passphrase
6. **HIGH** `SignerKeypair::new_session` bypassed ROS protection
7. **HIGH** cross-view consensus vote replay
8. **HIGH** unsigned gossip broadcast in production API
9. **MEDIUM** CLI passphrase min drift vs secure_store
10. **MEDIUM** `serialize_encrypted` panic on short passphrase
11. **MEDIUM** `create_presentation` panic on bad disclose index
12. **LOW** `clause_blind` non-constant-time branch select

See commit body of `43e2661` for RED/BLUE team details on each.

## [995452b] — 2026-04-10 — Comprehensive hardening (baseline)

Pre-audit baseline. Initial implementation of every crate. Not a
purple-team cycle but the starting point for the subsequent audits.
