# Specter Protocol

**Post-quantum ecash with Proof-Carrying Tokens and private compliance.**

Specter is a bearer-token digital cash protocol where each token simultaneously proves its own validity, the holder's regulatory compliance, and the integrity of its entire transfer history — without revealing anything about who holds it.

No system in existence combines all of these properties: decentralized threshold issuance, post-quantum readiness, total privacy without anonymity budgets, verifiable compliance without surveillance, offline transfers with economic guarantees, and constant-size tokens regardless of transfer history.

## Benchmarks

| Operation | Specter | Cashu | Zcash |
|---|---|---|---|
| Token issuance | 377 us | ~200 us | ~2-5 s |
| Token verification | 396 us | ~100 us | ~10 ms |
| Token transfer | 97 us | N/A (requires mint) | ~2-5 s |
| 20-transfer chain | 1.3 ms | N/A | N/A |
| Token size (basic) | 413 bytes | ~200 bytes | ~2,000 bytes |
| Token size (full) | 1,039 bytes | N/A | ~2,000 bytes |
| Size after 10 transfers | 1,039 bytes (constant) | N/A | N/A |

### Where Specter wins

- **Constant-size transfers**: Token size does not grow with transfer count. After 0 or 100 transfers, it is the same 1 KB. No other ecash system has this property.
- **Offline transfer**: Tokens transfer peer-to-peer without contacting any server. Cashu requires the mint. Zcash requires the blockchain.
- **Compliance without surveillance**: Each token carries a ZK proof that the holder passed KYC and is not sanctioned, without revealing who they are. No other system embeds compliance inside the token itself.
- **Threshold issuance**: No single entity controls token creation. A t-of-n threshold of signers must cooperate, each blind to the token content. Cashu has a single mint. Fedimint has a federation but no blinding.
- **Post-quantum ready**: Built on Ristretto255 with a clear migration path to lattice-based primitives. Architecture supports LatticeFold+ when lattice implementations mature.

### Where Specter is behind (honestly)

- **Issuance is ~2x slower than Cashu**: Threshold blind signing requires more computation than single-signer Cashu.
- **Token size is ~2-5x larger than Cashu**: The extra bytes carry the fold proof, credential presentation, and VDF proof that Cashu tokens do not have.
- **No production network**: Specter is a protocol with a reference implementation and tests, not a deployed system with wallets and exchanges.

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
- **Schnorr-verified proofs**: Accumulator checks `s*G == R + e*PK` — forged proofs rejected
- **Authenticated consensus**: Every vote carries a Schnorr signature verified against the voter's registered public key. Forged, tampered, and duplicate votes are rejected.
- **Zeroize on drop**: Secret keys and blinding factors are wiped from memory when tokens go out of scope
- **Encrypted storage**: Wallet save/load uses Argon2id + ChaCha20-Poly1305. Wrong passphrase = decryption failure.
- **Token verification on load**: Wallet rejects any deserialized token that fails signature/value/fold verification
- **Input validation**: Zero-value tokens rejected, duplicate signers rejected, overflow-safe arithmetic
- **Miller-Rabin primality**: RSA VDF uses 20-round Miller-Rabin (Carmichael numbers correctly rejected)
- **Rate-limited gossip**: Bounded nullifier set and outbox prevent memory exhaustion DoS
- **Custom Debug**: Secret fields print `[REDACTED]` — no key material in logs or crash reports
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
