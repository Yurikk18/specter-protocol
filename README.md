# Specter Protocol

Post-quantum ecash with Proof-Carrying Tokens (PCT) and private compliance.

Specter is a bearer-token digital cash protocol where each token is a single cryptographic object that simultaneously proves its own validity, the holder's regulatory compliance, and the integrity of its entire transfer history — without revealing anything about who holds it.

## Architecture

```
specter-primitives     Pedersen commitments, SIS commitments, Shamir secret sharing
specter-blind-sig      Schnorr blind signatures + threshold (t-of-n)
specter-fold           Proof accumulation with Fiat-Shamir transcripts
specter-credential     Anonymous credentials: issuance, selective disclosure
specter-core           PCT lifecycle: mint, transfer, verify, nullifiers
specter-offline        VDF time-locks + reputation bonds for offline payments
specter-net            P2P gossip protocol + BFT consensus for nullifier set
specter-cli            Demo CLI with protocol demonstration and benchmarks
```

## Implemented Features

### Cryptographic Primitives (specter-primitives)
- Pedersen commitments over Ristretto255 (homomorphic, vector)
- SIS-based commitments (lattice-based learning exercise)
- Shamir (t,n) secret sharing with Lagrange reconstruction
- Scalar utilities (random, hash-to-scalar via SHAKE-256)

### Blind Signatures (specter-blind-sig)
- Schnorr blind signature protocol (3-move, unlinkable)
- Threshold blind signatures (t-of-n via Shamir + blinding)
- Unlinkability: signer cannot correlate signing sessions with signatures

### Proof Accumulation (specter-fold)
- Hash-based proof accumulation with constant-size proofs
- Fiat-Shamir transcript for non-interactive proof generation
- Fold-on-transfer: each transfer folds into the accumulated proof
- Bounded recursion depth (configurable)

### Anonymous Credentials (specter-credential)
- Attribute-based credentials (KYC, sanctions, jurisdiction, age)
- Schnorr-based credential issuance
- Selective disclosure: prove specific attributes without revealing others
- ZK proof of knowledge for undisclosed attributes

### PCT Lifecycle (specter-core)
- Proof-Carrying Token with all components integrated
- Threshold blind minting with Pedersen value commitments
- Transfer with hash chain wear-out + fold accumulation
- Unified verification (signature + value + bound + fold + credential)
- Nullifier-based double-spend detection with blame protocol
- Optional compliance credentials embedded in tokens

### Offline Payments (specter-offline)
- VDF time-locks (iterated SHA-256, configurable iterations)
- Reputation bond registry (deposit, check coverage, slash, withdraw)
- Economic guarantees for offline spending

### Network Layer (specter-net)
- P2P message protocol (mint, transfer, sync, consensus messages)
- Gossip protocol for nullifier propagation with re-broadcasting
- Simplified BFT consensus (HotStuff-2 inspired)
- Leader rotation, quorum voting, block commitment
- Network node integrating gossip + consensus

## Quick Start

```bash
cargo build --workspace
cargo test --workspace
cargo run -p specter-cli -- demo
cargo run -p specter-cli --release -- benchmark
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
  (Verifier sees ONLY the ZK proof, not these values)
```

## Test Coverage

124 tests across 8 crates, covering:
- Cryptographic correctness (commitment, signature, credential roundtrips)
- Security properties (unlinkability, tamper detection, wrong-key rejection)
- Protocol lifecycle (mint -> transfer N times -> verify)
- Double-spend detection (nullifier collision)
- Recursion bound enforcement
- Gossip propagation (multi-node simulation)
- BFT consensus (proposal, voting, quorum, commit)
- Stress tests (100 tokens, 200-transfer chains)

## Project Roadmap

See `docs/phantasm-plano-completo.md` for the full 30-month plan.

**Implemented:** Phases 0-5 (foundations, PCT, credentials, fold, offline, network)

**Next steps for production:**
- Replace proof accumulator with Nova IVC / LatticeFold+ for true ZK
- Replace Schnorr credentials with BBS+ / OpenAC for standard compliance
- Migrate to lattice-based primitives for post-quantum security
- Replace local gossip with libp2p for real P2P networking
- Production BFT consensus (HotStuff-2 or Bullshark)
- Wallet application (CLI -> mobile)

## License

MIT OR Apache-2.0
