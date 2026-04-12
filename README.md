# Specter Protocol

> **Academic research implementation of post-quantum ecash with Proof-Carrying Tokens.**

Specter is an experimental cryptographic protocol developed as an academic exercise in applied cryptography. It explores how a bearer-token digital cash system could simultaneously prove its own validity, the holder's regulatory compliance, and the integrity of its transfer history — without revealing the holder's identity.

This project exists purely for **research and educational purposes**. It is a study of blind signature schemes, recursive proof folding, verifiable delay functions, anonymous credentials, and BFT consensus — implemented from the referenced academic papers as a learning exercise.

---

## Table of Contents

- [Research Context](#research-context)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Benchmarks](#benchmarks)
- [Feature Comparison](#feature-comparison)
- [Security Framework](#security-framework)
- [Protocol Specification](#protocol-specification)
- [References](#references)
- [Legal Disclaimer](#legal-disclaimer)
- [License](#license)

---

## Research Context

This implementation explores the intersection of several open problems in applied cryptography:

1. **Constant-size transferable proofs** — Can a bearer token maintain constant size across arbitrarily many P2P transfers? (via recursive Schnorr fold proofs, bounded by renewal)
2. **Privacy-preserving compliance** — Can a token prove regulatory compliance without revealing the holder's identity? (via anonymous credentials with selective disclosure)
3. **Offline double-spend deterrence** — Can economic incentives replace trusted hardware for offline payments? (via reputation bonds + social attestation chains)
4. **Post-quantum readiness** — Can the architecture support migration to lattice-based primitives? (via lazy PQ migration — PQ on mint signature only)

Each of these is grounded in peer-reviewed cryptographic literature (see [References](#references)).

---

## Architecture

The implementation is organized as a Rust workspace with 10 crates:

```
specter-primitives       Pedersen commitments, Shamir, scalar blinding, range proofs
specter-blind-sig        Schnorr blind signatures + threshold (t-of-n) + DKG + proactive resharing
specter-fold             Proof accumulation via signed transfer chain + Nova IVC (feature-gated)
specter-credential       Anonymous credentials with selective disclosure + revocation
specter-core             PCT lifecycle: mint, transfer, verify, wallet, nullifiers, WalletSigner
specter-offline          VDF time-locks (SHA-256 + RSA Wesolowski) + reputation bonds
specter-net              Authenticated gossip + BFT consensus + hybrid ML-DSA-65 votes
specter-cli              Demo, benchmarks, encrypted wallet, hybrid X25519+ML-KEM-768 handshake
specter-tee              AMD SEV-SNP confidential VM attestation (pure Rust, cross-platform verify)
specter-sbt              Symmetric Blind Tokens — threshold DH-OPRF + Chaum-Pedersen NIZK (PQ-ready)
```

### Dependency Graph

```
specter-primitives             (foundation — no internal dependencies)
    |
    +-- specter-blind-sig      (blind signatures, threshold signing, DKG, proactive resharing)
    +-- specter-fold           (proof accumulation, Fiat-Shamir transcripts)
    +-- specter-credential     (anonymous credentials, selective disclosure)
    +-- specter-offline        (VDF time-locks, reputation bonds)
    +-- specter-net            (BFT consensus, gossip, hybrid PQ votes)
    +-- specter-tee            (AMD SEV-SNP attestation, TCB policy enforcement)
    +-- specter-sbt            (threshold OPRF blind tokens, Chaum-Pedersen NIZK)
    |
    +-- specter-core           (depends on all above — full token lifecycle)
    |
    +-- specter-cli            (binary — demo, benchmarks, wallet, hybrid handshake)
```

### Cryptographic Primitives

| Primitive | Construction | Based On |
|-----------|-------------|----------|
| Commitment | Pedersen over Ristretto255 | Pedersen (1991) |
| Blind signature | Schnorr blind (3-move) + clause variant | Chaum (1983), Abe (2001) |
| Threshold signing | Shamir + Lagrange over Ristretto | Shamir (1979), Feldman VSS |
| DKG | Feldman VSS + Schnorr proof-of-knowledge | Feldman (1987) |
| Fold proof | Schnorr over SHAKE-256 Fiat-Shamir transcript | Fiat-Shamir (1986) |
| Recursive proof | Nova IVC (optional, feature-gated) | Kothapalli et al. (2022) |
| Credential | Schnorr signature over Pedersen vector commitment | Brands (1993) |
| VDF | RSA repeated squaring + Wesolowski proof | Wesolowski (2019) |
| OPRF | 2HashDH threshold DH-OPRF over Ristretto255 | Jarecki-Krawczyk-Xu (2014) |
| DDH-equality proof | Chaum-Pedersen NIZK (session + trustee bound) | Chaum-Pedersen (1993) |
| Nullifier | SHAKE-256(secret &#124;&#124; token_id) + SbtNullifier newtype | Standard construction |
| Encryption | ChaCha20-Poly1305 | RFC 8439 |
| KDF | Argon2id (128 MB, 4 iterations) | RFC 9106 |
| Scalar blinding | DPA-resistant blinded scalar mul | Side-channel hardening |
| Range proof | 64-bit bit-decomposition Chaum-Pedersen OR | Standard construction |
| Hybrid handshake | X25519 + ML-KEM-768 (FIPS 203) | NIST PQ Round 3 |
| Hybrid consensus | Schnorr + ML-DSA-65 (FIPS 204) | NIST PQ Round 3 |
| TEE attestation | AMD SEV-SNP via virtee/sev (pure Rust crypto_nossl) | AMD SEV-SNP ABI |
| TCB policy | Component-wise version floor + measurement pinning | AMD SEV-SNP best practice |

---

## Quick Start

```bash
# Build all crates
cargo build --workspace

# Run all 403 tests
cargo test --workspace

# Run the protocol demo
cargo run -p specter-cli -- demo

# Run benchmarks (release mode)
cargo run -p specter-cli --release -- benchmark

# Run Nova IVC tests (Linux/macOS only — pasta-msm assembly)
cargo test -p specter-fold --features nova -- --include-ignored
```

### CLI Usage

```
specter-cli setup               Create a new mint and empty wallet
specter-cli mint <value>        Mint a token with the given denomination
specter-cli balance             Show wallet balance and token inventory
specter-cli transfer            Transfer the first available token
specter-cli send <addr>         Send a token via encrypted TCP (ECDH + ChaCha20-Poly1305)
specter-cli receive <addr>      Receive a token via encrypted TCP
specter-cli save                Persist wallet to encrypted file
specter-cli load                Restore wallet from encrypted file
specter-cli demo                Full protocol demonstration
specter-cli benchmark           Performance measurements
```

The CLI uses `SPECTER_PASSPHRASE` environment variable for wallet encryption (minimum 8 characters). Release builds require it to be set explicitly.

### Demo Output

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

---

## Benchmarks

All Specter numbers measured in release mode on a desktop. External numbers from published papers and official documentation.

### Token Size

| System | Size | Source |
|--------|------|--------|
| Cashu proof | ~65 bytes | [NUT-00 spec](https://github.com/cashubtc/nuts/blob/main/00.md) |
| GNU Taler (Schnorr) | 64 bytes (sig only) | [Taler CS thesis](https://www.taler.net/papers/cs-thesis.pdf) |
| **Specter (basic)** | **413 bytes** | Measured |
| **Specter (full)** | **1,039 bytes** | Measured |
| Monero (1-in 2-out) | ~1,580 bytes | [monero-project/research-lab#79](https://github.com/monero-project/research-lab/issues/79) |
| Zcash Sapling (2-in 2-out) | 2,756 bytes | [zcash/zcash#4946](https://github.com/zcash/zcash/issues/4946) |
| Zcash Orchard (2-action) | 9,160 bytes | [zcash/zcash#4946](https://github.com/zcash/zcash/issues/4946) |
| **Specter after 100 transfers** | **1,039 bytes (constant)** | Measured |

### Operation Speed

| Operation | Specter | Zcash Sapling | BBS+ Credential |
|-----------|---------|---------------|-----------------|
| Issuance | **378 us** | 2,300 ms | 8.4 ms |
| Verification | **396 us** | 1.2 ms (Groth16) | 19 ms |
| Transfer (P2P local) | **97 us** | N/A (on-chain) | N/A |
| 20-transfer chain | **1.3 ms** | N/A | N/A |

> **Comparison note**: Specter transfer (97 us) is a local P2P operation with no network round-trip, comparable to handing physical cash. Zcash (2.3 s) includes Groth16 ZK proof generation + blockchain broadcast. These solve fundamentally different problems. Token size comparisons are fair since both are serialized bearer instruments.

### Honest Limitations

- **Token size ~6x larger than Cashu** (413-1,039 B vs ~65 B) — the extra bytes carry fold proof, credentials, and VDF that Cashu does not have
- **Not deployed** — this is a research prototype with 403 tests, not production software
- **Current benchmarks use classical curves** — PQ migration to lattice primitives will increase sizes significantly (estimated 300-600 KB per token with LatticeFold+)

---

## Feature Comparison

| Feature | Bitcoin | Monero | Zcash | Cashu | Fedimint | Specter |
|---------|---------|--------|-------|-------|----------|---------|
| Decentralized | Yes | Yes | Yes | No | Partial | **Yes (threshold)** |
| Private | No | Yes | Yes | Yes | Yes | **Yes** |
| Post-quantum ready | No | No | No | No | No | **Yes (hybrid ML-KEM + ML-DSA + SBT OPRF path)** |
| Compliance embedded | No | No | No | No | No | **Yes** |
| Offline transfer | No | No | No | No | Partial | **Yes (with bonds)** |
| Constant-size transfer | N/A | N/A | N/A | N/A | N/A | **Yes** |
| Transferable P2P | Yes | Yes | Yes | No | No | **Yes** |

---

## Security Framework

Three security pillars designed as a study of offline payment guarantees:

### Deterrence Theorem

For any adversary with bond B > token value V: E[profit] = V - B - reputation_cost < 0. Double-spending is economically irrational. This is formally stronger than TEE-based prevention, which relies on hardware trust assumptions broken by Spectre/Plundervolt/SGAxe.

### Social Attestation Chain

Each offline transfer creates a cryptographic witness. Witnesses form a mesh that detects double-spend between offline devices before anyone goes online. Conflicting attestation chains identify the cheater with cryptographic proof.

### Lazy PQ Migration

Post-quantum protection only on the mint signature (long-lived). Classical crypto for ephemeral fold proofs. PQ overhead paid once at issuance, not on every transfer.

### Implementation Security

See [docs/SECURITY.md](docs/SECURITY.md) for the full security audit report, including:

- Zeroize compliance matrix for all 17 secret-holding types
- Fiat-Shamir transcript security analysis
- Wallet encryption parameters (Argon2id 128 MB + ChaCha20-Poly1305)
- Blind signature ROS attack mitigations
- Dependency security status for all crates
- Known limitations and their mitigations

---

## Protocol Specification

- [docs/SPEC.md](docs/SPEC.md) — Formal protocol specification
- [docs/DESIGN.md](docs/DESIGN.md) — Complete design document with 37 referenced papers
- [docs/SECURITY.md](docs/SECURITY.md) — Security audit report

---

## References

### Foundational Papers

- D. Chaum, "Blind Signatures for Untraceable Payments" (CRYPTO 1983)
- A. Fiat, A. Shamir, "How to Prove Yourself: Practical Solutions to Identification and Signature Problems" (CRYPTO 1986)
- T. Pedersen, "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing" (CRYPTO 1991)
- M. Abe, "A Secure Three-Move Blind Signature Scheme for Polynomially Many Signatures" (EUROCRYPT 2001)
- B. Wesolowski, "Efficient Verifiable Delay Functions" (EUROCRYPT 2019)

### Recent Work

- A. Kothapalli, S. Setty, I. Tzialla, "Nova: Recursive Zero-Knowledge Arguments from Folding Schemes" (CRYPTO 2022)
- S. Agrawal et al., "Lattice-Based Blind Signatures: Short, Efficient, Round-Optimal" (CCS 2023)
- D. Boneh, B. Chen, "LatticeFold+: Efficient Folding over Lattices" (CRYPTO 2025)
- M. Faller et al., "Lattice-based Threshold Blind Signatures" (2025)
- G. Goodell et al., "Private Electronic Payments with Self-Custody and Compliance" (FC 2025)

---

## Legal Disclaimer

**THIS SOFTWARE IS PROVIDED STRICTLY FOR ACADEMIC RESEARCH AND EDUCATIONAL PURPOSES.**

This repository contains the source code of an experimental cryptographic protocol developed as a personal academic study in applied cryptography, with no commercial purpose, no deployment, and no association with any financial service, product, or company.

### No Financial Service

The author does not operate, has never operated, and has no intention of operating any financial service, money transmission business, payment institution, electronic money institution, virtual asset service provider (VASP), or any other regulated financial activity. This software has never been deployed, offered to the public, or used to process any real transaction of any kind.

### Academic and Educational Nature

This project is an academic exercise exploring cryptographic primitives described in peer-reviewed scientific literature (blind signatures, zero-knowledge proofs, verifiable delay functions, BFT consensus). The implementation follows published papers and is comparable to university coursework, thesis research, or open-source cryptographic libraries. The publication of cryptographic source code is a well-established academic practice.

### No Warranty and No Liability

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

**The author assumes no responsibility whatsoever for any use, misuse, or interpretation of this software by third parties.** Any person who downloads, compiles, modifies, or executes this code does so entirely at their own risk and is solely responsible for compliance with all applicable laws and regulations in their jurisdiction.

### Legal Protections for Publication

The publication of this source code is protected as free expression and academic freedom under applicable law, including but not limited to:

- **United States**: First Amendment to the Constitution; *Bernstein v. United States*, 176 F.3d 1132 (9th Cir. 1999), holding that source code is protected speech; *Junger v. Daley*, 209 F.3d 481 (6th Cir. 2000)
- **European Union**: Charter of Fundamental Rights, Article 13 (freedom of the arts and sciences), Article 11 (freedom of expression); Regulation (EU) 2016/679 Recital 153 (academic research)
- **Brazil**: Constituicao Federal, Art. 5 IX (free expression of intellectual and scientific activity); Marco Civil da Internet (Lei 12.965/2014, Art. 2, 3); Lei de Direitos Autorais (Lei 9.610/1998, Art. 46 — research and study exception)
- **Export control**: This software is publicly available encryption source code published in accordance with 15 CFR 742.15(b) (EAR exemption for publicly available source code). No export license is required.

### Not Legal Advice

This disclaimer does not constitute legal advice. If you have questions about the legality of using, modifying, or distributing this software in your jurisdiction, consult a qualified attorney.

---

## License

[MIT](LICENSE)

Copyright (c) 2026 Specter Protocol Contributors
