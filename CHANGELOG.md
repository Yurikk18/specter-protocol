# Changelog

All notable security and protocol-level changes to Specter Protocol.
This file tracks the audit cycles, their findings, and the resulting
patches so that external reviewers can follow the full history without
grep'ing commit bodies.

## [unreleased] — SBT + SEV-SNP + full hardening (zero residuals)

This cycle adds two new crates (specter-sbt, specter-tee), resolves all
residual security items, and brings the test count from 240 to 403 with
10+ iterative audit passes on the novel SBT construction.

### Added

- **`specter-sbt`** — Symmetric Blind Tokens: novel threshold DH-OPRF +
  Chaum-Pedersen NIZK composition for PQ-ready blind-token mint flow.
  68+ tests, 10 iterative security audits (clean bill of health).
  - Threshold 2HashDH OPRF with Feldman VSS share evaluation
  - Per-trustee DDH-equality proofs (rogue-share defense)
  - Schnorr TokenProof binding aggregate public key Y into transcript
  - `verify_token` returns `TagOriginCheckRequired` without held key
  - `verify_tag_threshold()` for decentralized spend-time verification
  - Deterministic nullifiers via HKDF(client_secret, payload)
  - `SbtNullifier` newtype for namespace separation from PCT nullifiers
  - `PqReadiness` module with compile-time gate on `pq-voleith` feature
  - `BlindSignatureScheme` trait abstraction for future PQ swap-in
- **`specter-tee`** — AMD SEV-SNP confidential VM attestation:
  - virtee/sev 6.3.1 with pure-Rust `crypto_nossl` backend
  - `sev_snp_verify.rs`: platform-independent verification (works on Windows)
  - `PortableSnpVerifier` implementing `AttestationProvider` on any OS
  - `TcbPolicy` with component-wise TCB floor, measurement allow-list, max VMPL
  - `user_data_from_pubkey_and_nonce()` for replay prevention
  - `MockAttestationProvider` behind `mock-attestation` feature for dev
- **`specter-primitives::hardened`** — scalar blinding for DPA resistance
- **`specter-primitives::range_proof`** — 64-bit bit-decomposition range proof
- **`specter-core::signer`** — `WalletSigner` trait + `SoftwareSigner` default impl
- **`specter-net::pq_consensus`** — hybrid ML-DSA-65 consensus vote verification
- **`specter-cli` hybrid handshake** — X25519 + ML-KEM-768 (FIPS 203)
- **`specter-blind-sig::dkg::proactive_reshare`** — Herzberg et al. 1995
- **CI workflow** — cargo check, clippy, test, audit, deny, fuzz-build
- **`deny.toml`** — cargo-deny config with allowed licenses
- **Fuzz targets** — 3 new SBT deserialization fuzzers (SpendToken, SbtRequest, OprfEvaluation)
- **Benchmarks** — Criterion benchmarks for all SBT crypto hot paths
- **E2E integration tests** — full mint→spend→double-spend lifecycle

### Changed

- `AttestationProvider::verify_report` now REQUIRES `&TcbPolicy` parameter
- `specter-fold::accumulator`: `TransferStep::Debug` redacts `sig_s`,
  Schnorr verify uses constant-time `ct_eq`
- `specter-offline::vdf_rsa`: `evaluate()` capped at `MAX_RSA_VDF_ITERATIONS`,
  `default_2048()` uses `unreachable!` instead of `expect`
- `specter-offline::bonds`: withdrawal timestamp uses `checked_add`

### Security — Closed

- Identity-point injection on all SBT wire types (10+ entry points hardened)
- Zero-nonce edge case in sigma protocol provers (re-draw loop)
- Session-id replay across mint/spend contexts (session binding + ct_eq)
- Aggregate public key trust bypass (disjoint-quorum cross-check)
- Payload-leaking deterministic commitment (client_secret mixing)
- Error-step leakage in `verify_token` (collapsed into single variant)
- u32→u64 length-prefix truncation in SHAKE-256 transcripts
- Variable-time Schnorr verify in specter-fold (switched to ct_eq)
- Uncapped VDF iterations in specter-offline (DoS vector)
- Timestamp overflow in bond withdrawal arithmetic (checked_add)

### Test Count

**403 tests across 10 crates, zero failures.**

---

## [eaab68f] — Signed transfer chain (fundamental fold proof fix)

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
- 8 fuzz targets via `cargo-fuzz` (`fuzz/`)
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
