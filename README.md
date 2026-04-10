# Specter Protocol

Post-quantum ecash with Proof-Carrying Tokens (PCT) and private compliance.

Specter is a bearer-token digital cash protocol where each token is a single cryptographic object that simultaneously proves its own validity, the holder's regulatory compliance, and the integrity of its entire transfer history — without revealing anything about who holds it.

## Architecture

```
specter-primitives     Pedersen commitments, SIS commitments, Shamir secret sharing, scalar utilities
specter-blind-sig      Schnorr blind signatures (single + threshold t-of-n)
specter-core           Proof-Carrying Token lifecycle: mint, transfer, verify, nullifier
specter-cli            Demo CLI with protocol demonstration and benchmarks
specter-fold           (Phase 1) Recursive proof folding via Nova IVC
specter-credential     (Phase 1) Anonymous credentials for compliance layer
```

## What Works

- **Pedersen commitments** over Ristretto255 with homomorphic property
- **SIS commitments** (lattice-based learning exercise)
- **Shamir secret sharing** (t,n) with Lagrange reconstruction
- **Schnorr blind signatures** — 3-move protocol, unlinkable
- **Threshold blind signatures** — t-of-n threshold via Shamir + blinding
- **Proof-Carrying Tokens** — mint, transfer, verify full lifecycle
- **Double-spend detection** — nullifier-based with blame protocol
- **Hash chain wear-out** — bounded transfer count with renewal
- **CLI demo** — full protocol demonstration + benchmarks

## Quick Start

```bash
# Build everything
cargo build --workspace

# Run all tests (70+ unit tests + 10 integration tests)
cargo test --workspace

# Run the protocol demo
cargo run -p specter-cli -- demo

# Run benchmarks
cargo run -p specter-cli --release -- benchmark
```

## Demo Output

```
=== Specter Protocol Demo ===

[1/5] Setting up threshold mint (2-of-3)...
[2/5] Minting token (value: 1000, signers: [1, 3])...
[3/5] Verifying freshly minted token...
  ALL VALID: true
[4/5] Transferring token 5 times...
  Transfer 1: count=1/20, valid=true
  Transfer 2: count=2/20, valid=true
  ...
[5/5] Demonstrating double-spend detection...
  First spend:  true
  Second spend: false (DOUBLE SPEND!)
```

## Benchmark Results (release mode)

| Operation | Time |
|-----------|------|
| Mint setup (2-of-3) | ~325us |
| Token issuance (threshold blind sign) | ~349us |
| Token verification | ~96us |
| Token transfer | ~1.4us |
| 20-transfer chain | ~25us |
| Token size (prototype) | 240 bytes |

## Project Status

**Phase 0** (complete): Cryptographic foundations over elliptic curves.

**Phase 1** (next): PCT prototype with Nova IVC recursive folding, OpenAC credentials, constant-size tokens.

**Phase 3** (future): Migration to post-quantum lattice-based primitives (LatticeFold+, lattice blind signatures).

See `docs/phantasm-plano-completo.md` for the full 30-month roadmap.

## License

MIT OR Apache-2.0
