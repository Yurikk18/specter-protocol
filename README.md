# Specter Protocol

Post-quantum ecash with Proof-Carrying Tokens (PCT) and private compliance.

Specter is a bearer-token digital cash protocol where each token is a single cryptographic object that simultaneously proves its own validity, the holder's regulatory compliance, and the integrity of its entire transfer history -- without revealing anything about who holds it.

## Status

**Phase 0** -- Building cryptographic foundations:
- Pedersen commitments over Ristretto255
- SIS-based commitments (lattice introduction)
- Schnorr blind signatures

## Building

```bash
cargo build --workspace
cargo test --workspace
cargo bench
```

## License

MIT OR Apache-2.0
