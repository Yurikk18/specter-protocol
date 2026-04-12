# Security Audit Report

## Overview

The Specter Protocol has undergone multiple rounds of automated Purple Team security auditing covering all 10 crates, every cryptographic operation, and every dependency. This document summarizes the findings and the mitigations applied.

**Audit scope**: Full codebase (all `.rs` files, all `Cargo.toml`, all dependencies)
**Methodology**: Iterative attack-fix-revalidate cycles with parallel Red Team analysis covering cryptographic primitives, proof systems, protocol logic, network layer, credentials, TEE attestation, OPRF construction, and infrastructure
**Final state**: 403 tests passing, 0 failures, 10+ iterative audit passes on specter-sbt (clean), clean `cargo build --workspace`

### Additional Audited Components (2026-04-11/12)

| Component | Audit Passes | Findings Fixed | Status |
|-----------|-------------|----------------|--------|
| specter-sbt (Symmetric Blind Tokens) | 10 | 15+ (CRITICAL to INFO) | Clean |
| specter-tee (AMD SEV-SNP attestation) | 2 | 5 (MEDIUM to LOW) | Clean |
| specter-fold (signed transfer chain) | 1 (re-audit) | 2 (MEDIUM) | Clean |
| specter-offline (VDF + bonds) | 1 (re-audit) | 3 (HIGH to MEDIUM) | Clean |

## Dependency Security Status

| Crate | Version | Status |
|-------|---------|--------|
| curve25519-dalek | 4.1.3 | Patched (RUSTSEC-2024-0344 timing fix included) |
| chacha20poly1305 | 0.10.1 | No known advisories |
| argon2 | 0.5.3 | No known advisories |
| sha2 | 0.10.9 | No known advisories |
| sha3 | 0.10.8 | No known advisories |
| rand | 0.8.5 | No known advisories |
| rand_core | 0.6.4 | Patched (RUSTSEC-2021-0023 fix included) |
| zeroize | 1.8.2 | No known advisories |
| borsh | 1.6.1 | Patched (RUSTSEC-2023-0033 fix included) |
| num-bigint | 0.4.6 | Patched (GHSA-v935-pqmr-g8v9 fix included) |
| nova-snark | 0.29 | **Outdated** — optional feature flag, recommend upgrade to 0.71+ |
| sev (virtee) | 6.3.1 | No known advisories (crypto_nossl backend) |
| ml-kem | 0.2.1 | No known advisories (FIPS 203 ML-KEM-768) |
| ml-dsa | 0.1.0-rc.8 | Pre-release (FIPS 204 ML-DSA-65) |
| p384 | 0.13.1 | No known advisories (SEV-SNP ECDSA verification) |
| subtle | 2.6.1 | No known advisories (constant-time ops) |
| bincode | 1.3.3 | No known advisories (SEV-SNP wire format) |

## Security Architecture

### Zeroize Compliance Matrix

Every type holding secret material implements `Drop` with `zeroize`:

| Type | Crate | Secret Fields | Zeroize |
|------|-------|---------------|---------|
| `ProofCarryingToken` | specter-core | `owner_secret` | Yes |
| `UserTokenSecrets` | specter-core | `owner_secret`, `value_blinding` | Yes |
| `Share` | specter-primitives | `y` (secret share) | Yes |
| `SignerSession` | specter-blind-sig | `k` (nonce) | Yes |
| `BlindingFactors` | specter-blind-sig | `alpha`, `beta` | Yes |
| `ClauseSession` | specter-blind-sig | `k0`, `k1` | Yes |
| `ClauseBlindingFactors` | specter-blind-sig | `alpha`, `beta` | Yes |
| `SignerSessionState` | specter-blind-sig | `nonce` | Yes |
| `ThresholdKeyset` | specter-blind-sig | `shares` (HashMap values) | Yes |
| `SignerKeypair` | specter-blind-sig | `secret` | Yes |
| `ValidatorKey` | specter-net | `secret_key` | Yes |
| `Issuer` | specter-credential | `secret` | Yes |
| `Credential` | specter-credential | `blinding` | Yes |
| Argon2 derived key | specter-core | `key [u8; 32]` | Yes (explicit) |
| ECDH shared key | specter-cli | `shared_key [u8; 32]` | Yes (explicit) |
| ECDH ephemeral secret | specter-cli | `my_sk` | Yes (explicit) |

### Custom Debug Redaction

Types with secret fields use custom `Debug` impls that print `[REDACTED]`:

- `ProofCarryingToken` — redacts `owner_secret`
- `SignerKeypair` — redacts `secret`
- `Share` — redacts `y`
- `Credential` — redacts `blinding`

### Non-Clone Security Types

These types deliberately do not implement `Clone` to prevent secret duplication:

| Type | Reason |
|------|--------|
| `ProofCarryingToken` | Bearer instrument — cloning duplicates economic value |
| `ValidatorKey` | Secret signing key — copies bypass Drop zeroization |
| `SignerSession` | Secret nonce — duplication enables key recovery |

### Fiat-Shamir Transcript Security

The `Transcript` type (SHAKE-256 based) provides:
- **Length-prefixed labels**: Both label and data are length-prefixed to prevent cross-field ambiguity
- **Challenge chaining**: After squeezing a challenge, the 64-byte output is re-absorbed into the transcript
- **Domain separation**: Every transcript starts with `b"specter-transcript:" || domain`
- **Full-width challenges**: 64 bytes squeezed, reduced to scalar via `from_bytes_mod_order_wide`

### Wallet Encryption

- **KDF**: Argon2id with 128 MB memory, 4 iterations, 4 parallelism lanes
- **Cipher**: ChaCha20-Poly1305 (IND-CCA2 secure AEAD)
- **Salt**: 16 bytes from CSPRNG, unique per encryption
- **Nonce**: 12 bytes from CSPRNG, unique per encryption
- **Minimum passphrase**: 8 bytes (enforced via `Result` return, not panic)
- **Key zeroization**: Derived key is zeroized immediately after use

### Nullifier Persistence

- **In-memory**: `HashSet<[u8; 32]>` with atomic check-and-insert
- **File-backed**: Append-only binary format with `sync_all()` (fsync) for crash safety
- **Path validation**: Rejects `..` path traversal
- **Size limit**: 320 MB / 10M nullifiers maximum
- **Graceful degradation**: I/O errors logged, nullifier kept in memory

### Blind Signature Security

- **ROS attack**: `RateLimitedSigner` enforces max 1 concurrent session for standard blind Schnorr. Clause blind variant (Abe 2001) available for concurrent use
- **Blinding factors**: Generated via `random_scalar()` (OsRng CSPRNG, uniform over group order)
- **DKG**: Includes Schnorr proof-of-knowledge per participant to prevent rogue-key attacks
- **Share verification**: Feldman VSS verification against polynomial commitments
- **Message-length prefix**: Both `schnorr_blind` and `clause_blind` hash challenges include message length to prevent concatenation attacks

### Consensus Security

- **BFT threshold**: Standard 2f+1 quorum for n >= 4. Warning emitted for n < 4 (zero fault tolerance)
- **Vote authentication**: Schnorr signatures on every vote, verified against registered public keys
- **View replay prevention**: Vote messages include view number in the signed payload
- **Equivocation detection**: Tracks seen proposals per (height, leader) pair
- **Nullifier DoS protection**: `pending_nullifiers` uses `HashSet` (O(1) lookup), capped at 100K
- **Gossip authentication**: `NullifierBroadcast` messages include signature fields

### Credential Security

- **5-attribute commitment**: `[kyc, sanctions, jurisdiction, age, expires_at]` all committed in Pedersen vector
- **Expiry binding**: `expires_at` is part of the Pedersen commitment — cannot be modified after issuance
- **Selective disclosure**: ZK proof of knowledge for hidden attributes
- **Presentation bounds check**: Out-of-range disclosure indices are rejected (prevents panic)
- **Dual revocation**: By commitment hash (specific credential) or by holder ID (all credentials for a user)
- **Blinding zeroization**: `Credential.blinding` is zeroized on drop, redacted in Debug

### Bond Security

- **Evidence-based slashing**: `slash()` requires two distinct conflicting nullifiers as proof
- **Lock period**: Withdrawal requires waiting period (default 7 days) during which bonds can still be slashed
- **Exposure tracking**: Offline spending tracked with overflow-safe arithmetic
- **Duplicate prevention**: `deposit()` returns error if owner already has active bond

### RSA VDF Security

- **Zero iterations rejected**: Both SHA-256 and RSA VDF verifiers reject T=0
- **Degenerate inputs rejected**: RSA VDF rejects input <= 1 (trivially known outputs)
- **Iteration cap**: MAX_VDF_ITERATIONS = 10,000,000 for both variants
- **RSA-2048 modulus**: Uses the RSA Factoring Challenge number (unknown factorization)
- **Miller-Rabin**: 20 rounds with deterministic witnesses (correctly rejects Carmichael numbers)
- **Wesolowski proof**: O(log T) verification instead of O(T) recomputation

## Known Limitations

### Fold Proof at step > 0

The Schnorr-based fold proof system provides full verification at genesis (step 0) but has a known theoretical limitation at step > 0: an attacker who generates their own keypair can construct a valid-looking proof without performing actual transfers. This is inherent to constant-size Schnorr proofs without recursive SNARKs.

**Mitigation**: The fold proof is NOT the security boundary. Token authenticity relies on the mint's threshold blind signature (unforgeable without t-of-n signers) and the nullifier set (prevents double-spend). The fold proof provides structural integrity and transfer counting.

**Resolution path**: Nova IVC (feature-gated behind `nova`) provides true recursive SNARK verification where each step constrains the actual transfer data. The Nova circuit currently only constrains step counting and needs to be extended to constrain `new_owner_data`.

### Nova IVC Status

The optional Nova IVC module (`specter-fold/src/nova_ivc.rs`, behind the `nova` feature flag):
- Uses `nova-snark 0.29` which should be upgraded to 0.71+
- The circuit currently constrains only step increment, not transfer data
- Only compiles on Linux/macOS (pasta-msm assembly incompatible with Windows)
- Tests are `#[ignore]` and require explicit opt-in

### num-bigint Timing

The `num-bigint` crate (used for RSA VDF) does not provide constant-time operations. The RSA VDF is used for time-locking (public computation), not for secret key operations, so timing leaks do not compromise key material. However, VDF evaluation timing could theoretically reveal the iteration count.
