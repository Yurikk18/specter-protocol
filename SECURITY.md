# Security Policy

## Supported Versions

Specter Protocol is pre-1.0 and under active development. Only the
`main` branch of [Yurikk18/specter-protocol](https://github.com/Yurikk18/specter-protocol)
is considered supported; older branches and tags receive no security
fixes.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in Specter
Protocol, please **DO NOT** open a public GitHub issue. Instead, file
a private security advisory via GitHub:

> https://github.com/Yurikk18/specter-protocol/security/advisories/new

Include:

- a description of the vulnerability and the affected component
- a minimal proof-of-concept that reproduces the issue
- the commit SHA and build configuration you tested against
- any suggested mitigation or patch

We will acknowledge private reports within 7 days and aim to publish
a fix within 90 days of triage.

## Threat Model

See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for the authoritative
description of what Specter Protocol protects, what it does not
protect, and which adversaries are in scope.

## Audit History

| Date       | Scope                                  | Findings | Status                                             |
| ---------- | -------------------------------------- | -------- | -------------------------------------------------- |
| 2026-04-10 | 5-pass purple-team crypto audit        | 12       | All fixed in `43e2661`                             |
| 2026-04-11 | 15-pass continuous audit loop          | 3 + R/A  | All fixed in `edf799a`                             |
| 2026-04-11 | Fundamental fold proof replacement     | 1        | Signed-chain accumulator in `eaab68f`              |
| 2026-04-11 | specter-sbt 10-pass iterative audit    | 15+      | All fixed across `29c3b80`, `64a8137`, `a77ad3a`   |
| 2026-04-12 | specter-tee security audit             | 5        | All fixed in `64a8137`                             |
| 2026-04-12 | specter-fold + specter-offline audit   | 5        | All fixed in `a77ad3a`                             |

All historical findings with attack vectors and patches are documented
inside the commit bodies — run `git log --format=full` on the `main`
branch for the complete record.

## Cryptographic Components

| Primitive              | Library / Construction                   | Status |
| ---------------------- | ---------------------------------------- | ------ |
| Elliptic curve         | Ristretto255 (`curve25519-dalek 4.1.3`)  | ✅      |
| Blind signatures       | Schnorr blind + clause-blind variants    | ✅      |
| Threshold / DKG        | Feldman VSS + Schnorr PoK                | ✅      |
| Commitments            | Pedersen with NUMS generators            | ✅      |
| Transfer proofs        | Signed transfer chain (SIGMA-I style)    | ✅      |
| Fiat-Shamir transcripts| SHAKE-256 with domain separation         | ✅      |
| Authenticated encryption | ChaCha20-Poly1305                      | ✅      |
| Password-based KDF     | Argon2id (128 MiB, 4 iter, 4 parallelism)| ✅      |
| Memory hardening       | `mlock` / `VirtualLock` + `zeroize`      | ✅      |
| Nullifier set          | `NullifierSet` + `ConcurrentNullifierSet`| ✅      |
| BFT consensus          | HotStuff-like with Schnorr-signed votes  | ✅      |
| Hybrid PQ consensus    | ML-DSA-65 (FIPS 204) dual-signed votes   | ✅      |
| Hybrid PQ handshake    | X25519 + ML-KEM-768 (FIPS 203)           | ✅      |
| Attestation chains     | v3 hash binding sender pubkey            | ✅      |
| Anonymous credentials  | Schnorr-based selective disclosure       | ✅      |
| TEE attestation        | AMD SEV-SNP (virtee/sev, crypto_nossl)   | ✅      |
| TCB policy             | Component-wise floor + measurement pin   | ✅      |
| Threshold OPRF (SBT)   | 2HashDH + Chaum-Pedersen DDH-equality    | ✅      |
| Token NIZK (SBT)       | Schnorr PoK + aggregate key binding      | ✅      |
| Scalar blinding        | DPA-resistant blinded scalar multiply    | ✅      |
| Range proof            | 64-bit Chaum-Pedersen OR bit-decomp      | ✅      |
| PQ readiness gate      | compile_error! on pq-voleith feature     | ✅      |
| Proactive resharing    | Herzberg et al. 1995 DKG key rotation    | ✅      |

## Dependency Audit

Workspace is scanned with `cargo audit` against the RustSec advisory
database. Zero actual vulnerabilities as of the most recent audit. Four
informational warnings (`unmaintained` / `unsound`) are documented in
[`audit.toml`](./audit.toml) with rationale for each.

## Known Residual Limitations

1. **Nova-snark 0.29.0 lags upstream (0.71.0).** Only reachable via the
   optional `nova` feature which is disabled by default. The production
   fold proof uses the signed transfer chain in
   `specter-fold::accumulator`.
2. **Hash-based VDF is ASIC-accelerable.** Marked `#[deprecated]`;
   production should use `specter-offline::vdf_rsa` (Wesolowski over
   RSA-2048). `evaluate()` is now capped at `MAX_RSA_VDF_ITERATIONS`.
3. **`mlock` is best-effort.** Falls back to zeroize-on-drop when the
   operating system denies lock (e.g., `RLIMIT_MEMLOCK` too low).
4. **Distributed nullifier set is not network-partition tested.** The
   BFT consensus layer has the primitives (signed votes, view-change,
   equivocation detection) but has not been stress-tested against
   long-running partitions.
5. **Post-quantum.** Classical EC primitives (Ristretto255, Schnorr,
   Pedersen) are vulnerable to Shor's algorithm. **Mitigations**:
   - Hybrid ML-KEM-768 handshake (specter-cli, `pq-handshake` feature)
   - Hybrid ML-DSA-65 consensus votes (specter-net, `pq-consensus` feature)
   - SBT OPRF construction designed for lattice-OPRF swap-in when
     Rust ecosystem matures (Leap OPRF, Eurocrypt 2025)
   - `PqReadiness::detect()` runtime check + `compile_error!` gate on
     `pq-voleith` feature prevents premature PQ claims
   - Symmetric primitives (Argon2id, ChaCha20-Poly1305, SHAKE-256)
     remain PQ-sound at 128-bit security.
6. **SEV-SNP fixture test pending.** The portable verification path
   (`sev_snp_verify.rs`) compiles and links on Windows via `crypto_nossl`
   but has not been tested against captured AMD cert chains from real
   hardware. Requires Azure CVM access for fixture generation.

## Build-Time Checks

| Gate                   | Command                                 |
| ---------------------- | --------------------------------------- |
| Compile                | `cargo check --workspace`               |
| Lints                  | `cargo clippy --workspace -- -D warnings` |
| Tests                  | `cargo test --workspace`                |
| Dependency CVEs        | `cargo audit`                           |
| Fuzz (Linux/macOS)     | `cargo +nightly fuzz run <target>` — see [`fuzz/README.md`](./fuzz/README.md) |

All of these must pass on every commit that touches cryptographic code.
