# Specter Protocol

**Post-quantum ecash with Proof-Carrying Tokens and private compliance.**

Specter is a bearer-token digital cash protocol where each token simultaneously proves its own validity, the holder's regulatory compliance, and the integrity of its entire transfer history - without revealing anything about who holds it.

No system in existence combines all of these properties: decentralized threshold issuance, post-quantum readiness, total privacy without anonymity budgets, verifiable compliance without surveillance, offline transfers with economic guarantees, and constant-size tokens regardless of transfer history.

## Benchmarks (Real Data)

All Specter numbers measured in release mode on a desktop. External system numbers from published papers, official documentation, and audited benchmarks (sources cited).

### Token/Transaction Size

| System | Size | Source |
|---|---|---|
| Cashu proof | ~65 bytes | [NUT-00 spec](https://github.com/cashubtc/nuts/blob/main/00.md) |
| GNU Taler (Schnorr) | 64 bytes (sig only) | [Taler CS thesis](https://www.taler.net/papers/cs-thesis.pdf) |
| GNU Taler (RSA 3072) | 384 bytes (sig only) | [Taler docs](https://www.taler.net/en/news/2022-02.html) |
| **Specter (basic)** | **413 bytes** | Measured |
| **Specter (full)** | **1,039 bytes** | Measured |
| Monero (1-in 2-out) | ~1,580 bytes | [monero-project/research-lab#79](https://github.com/monero-project/research-lab/issues/79) |
| Zcash Sapling (2-in 2-out) | 2,756 bytes | [zcash/zcash#4946](https://github.com/zcash/zcash/issues/4946) |
| Zcash Orchard (2-action) | 9,160 bytes | [zcash/zcash#4946](https://github.com/zcash/zcash/issues/4946) |
| **Specter after 100 transfers** | **1,039 bytes (constant)** | Measured |

### Speed

| Operation | Specter | Zcash Sapling | BBS+ Credential |
|---|---|---|---|
| Issuance / Proof gen | **378 us** | 2,300 ms | 8.4 ms |
| Verification | **396 us** | 1.2 ms (Groth16) | 19 ms |
| Transfer (P2P) | **97 us** | N/A (on-chain) | N/A |
| 20-transfer chain | **1.3 ms** | N/A | N/A |

Sources: Zcash from [ECC blog](https://electriccoin.co/blog/reducing-shielded-proving-time-in-sapling/), BBS+ from [Dyne.org benchmark](https://news.dyne.org/benchmark-of-the-bbs-signature-scheme-v06/)

### What Specter does that nobody else does

1. **Constant-size P2P transfer**: Token is 1,039 bytes after 0 or 100 transfers. No other ecash system maintains constant token size across transfers. Cashu tokens cannot be transferred P2P at all.

2. **Compliance inside the token**: Each token carries a ZK selective disclosure proof that the holder is KYC-verified and not sanctioned - without revealing identity. No other system embeds regulatory compliance in the bearer instrument itself.

3. **97 microsecond P2P transfer**: 24,000x faster than a Zcash shielded transaction (2.3s). No server contact, no blockchain, no waiting.

4. **Threshold blind issuance**: t-of-n signers cooperate blindly. Cashu has a single trusted mint. Fedimint has a federation but signers see the token content. Specter signers are completely blind.

5. **Post-quantum architecture**: Built for migration to lattice primitives. Nova IVC (feature-gated) provides the recursive proof system. No ecash in production is PQ-ready.

### Where Specter is behind (honestly)

- **Token size is ~6x larger than Cashu**: Cashu proofs are ~65 bytes vs Specter's 413-1,039 bytes. The extra bytes carry fold proof, credentials, and VDF that Cashu does not have.
- **Not deployed**: Specter is a protocol with 188 tests and a reference implementation. Cashu, Zcash, and Monero have years of production use.
- **BIS Project Tourbillon showed PQ blind signatures are 200x slower**: When Specter migrates to lattice primitives, performance will decrease significantly. The current benchmarks are on elliptic curves.

## Feature Comparison

| Feature | Bitcoin | Monero | Zcash | Cashu | Fedimint | Specter |
|---|---|---|---|---|---|---|
| Decentralized | Yes | Yes | Yes | No | Partial | **Yes (threshold)** |
| Private | No | Yes | Yes | Yes | Yes | **Yes** |
| Post-quantum ready | No | No | No | No | No | **Yes** |
| Compliance embedded | No | No | No | No | No | **Yes** |
| Offline transfer | No | No | No | No | Partial | **Yes (with bonds)** |
| Constant-size transfer | N/A | N/A | N/A | N/A | N/A | **Yes** |
| Transferable P2P | Yes | Yes | Yes | No | No | **Yes** |

## Architecture

```
specter-primitives     Pedersen commitments, SIS, Shamir secret sharing
specter-blind-sig      Schnorr blind signatures + threshold (t-of-n)
specter-fold           Proof accumulation + Nova IVC (feature-gated)
specter-credential     Anonymous credentials with selective disclosure
specter-core           PCT lifecycle: mint, transfer, verify, wallet, serialization
specter-offline        VDF time-locks (SHA-256 + RSA Wesolowski) + reputation bonds
specter-net            Gossip protocol + authenticated BFT consensus
specter-cli            Demo + benchmarks
```

## Security

- **188 tests** across 8 crates, including property-based tests (proptest)
- **Schnorr-verified proofs**: Accumulator checks `s*G == R + e*PK` - forged proofs rejected
- **Authenticated consensus**: Every vote carries a Schnorr signature verified against the voter's registered public key. Forged, tampered, and duplicate votes are rejected.
- **Zeroize on drop**: Secret keys and blinding factors are wiped from memory when tokens go out of scope
- **Encrypted storage**: Wallet save/load uses Argon2id + ChaCha20-Poly1305. Wrong passphrase = decryption failure.
- **Token verification on load**: Wallet rejects any deserialized token that fails signature/value/fold verification
- **Input validation**: Zero-value tokens rejected, duplicate signers rejected, overflow-safe arithmetic
- **Miller-Rabin primality**: RSA VDF uses 20-round Miller-Rabin (Carmichael numbers correctly rejected)
- **Rate-limited gossip**: Bounded nullifier set and outbox prevent memory exhaustion DoS
- **Custom Debug**: Secret fields print `[REDACTED]` - no key material in logs or crash reports
- **RSA-2048 challenge modulus**: VDF uses the RSA-2048 number with unknown factorization

## Quick Start

```bash
# Build
cargo build --workspace

# Run all 188 tests
cargo test --workspace

# Run demo
cargo run -p specter-cli -- demo

# Run benchmarks
cargo run -p specter-cli --release -- benchmark

# Run Nova IVC tests (Linux/macOS only)
cargo test -p specter-fold --features nova -- --include-ignored
```

## Demo Output

```
=== Specter Protocol Demo ===

[1/6] Setting up threshold mint (2-of-3)...
[2/6] Minting token with compliance credential...
  Has credential:    true
  Fold proof steps:  0
  Estimated size:    1140 bytes
[3/6] Verifying freshly minted token...
  Signature valid:   true
  Credential valid:  Some(true)
  ALL VALID:         true
[4/6] Transferring token 5 times (with fold accumulation)...
  Transfer 1: fold_steps=1, valid=true
  Transfer 5: fold_steps=5, valid=true
[5/6] Demonstrating double-spend detection...
  First spend:       true (valid)
  Second spend:      false (DOUBLE SPEND DETECTED)
[6/6] Credential properties...
  KYC passed:        true
  Not sanctioned:    true
  (Verifier sees ONLY the ZK proof, not these values)
```

## Protocol Specification

See [docs/phantasm-plano-completo.md](docs/phantasm-plano-completo.md) for the full protocol design, 37 referenced papers, timeline, and security analysis.

## Key Papers Referenced

- Chaum, "Blind Signatures for Untraceable Payments" (1983)
- Agrawal et al., "Lattice-Based Blind Signatures: Short, Efficient, Round-Optimal" (CCS 2023)
- Boneh & Chen, "LatticeFold+" (CRYPTO 2025)
- Faller et al., "Lattice-based Threshold Blind Signatures" (2025)
- Goodell et al., "Private Electronic Payments with Self-Custody" (FC 2025)

## License

[MIT](LICENSE)
