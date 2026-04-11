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
| 2026-04-11 | Fundamental fold proof replacement     | 1        | Signed-chain accumulator, pushed in this commit    |

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
| Attestation chains     | v3 hash binding sender pubkey            | ✅      |
| Anonymous credentials  | Schnorr-based selective disclosure       | ✅      |

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
   RSA-2048).
3. **`mlock` is best-effort.** Falls back to zeroize-on-drop when the
   operating system denies lock (e.g., `RLIMIT_MEMLOCK` too low).
4. **Distributed nullifier set is not network-partition tested.** The
   BFT consensus layer has the primitives (signed votes, view-change,
   equivocation detection) but has not been stress-tested against
   long-running partitions.
5. **Quantum.** All elliptic-curve primitives (Ristretto255, Schnorr,
   Pedersen, Nova, SIGMA-I) are vulnerable to Shor's algorithm in a
   post-quantum world. Symmetric primitives (Argon2id, ChaCha20-Poly1305,
   SHAKE-256) remain post-quantum sound at 128-bit security.

## Build-Time Checks

| Gate                   | Command                                 |
| ---------------------- | --------------------------------------- |
| Compile                | `cargo check --workspace`               |
| Lints                  | `cargo clippy --workspace -- -D warnings` |
| Tests                  | `cargo test --workspace`                |
| Dependency CVEs        | `cargo audit`                           |
| Fuzz (Linux/macOS)     | `cargo +nightly fuzz run <target>` — see [`fuzz/README.md`](./fuzz/README.md) |

All of these must pass on every commit that touches cryptographic code.
