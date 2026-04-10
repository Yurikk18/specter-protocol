# Specter Project: Proof-Carrying Tokens - Post-Quantum Ecash with Private Compliance

## Vision

A new **cryptographic primitive** - the Proof-Carrying Token (PCT) - that transforms digital money into a self-verifiable object that simultaneously proves its validity, the bearer's compliance, and the integrity of its entire history, without revealing anything about who owns it.

Specter is not "yet another ecash with extra features." It is a **new category**: bearer tokens that carry their own proofs, built on post-quantum cryptography from day 1.

Simultaneous properties:
- **Decentralized** - issuance by threshold of nodes, no central authority
- **Post-quantum** - lattice-based from the foundation, not as a late migration
- **Private** - no anonymity budgets, no tracking, no surveillance
- **Compliant** - each token proves the bearer passed KYC and is not sanctioned, WITHOUT revealing identity
- **Offline** - works without internet with economic guarantees (not perfect, but strictly better than any competitor)
- **Transferable** - tokens pass from hand to hand with constant size (does not grow with transfers)
- **Open source** - protocol + code, Tor model

As a bearer instrument, the protocol is agnostic to who uses it - it works for any entity that possesses the key, whether human or autonomous software, without modifications to the protocol.

---

## The Core Innovation: Proof-Carrying Tokens (PCT)

### The Fundamental Problem

In every existing ecash system, a token is one thing and the proofs of its validity are separate things:

```
Conventional system:
  Token = blind_signature (20-36KB in lattices)
        + ZK_proof_de_validade (100-200KB)
        + credential_de_compliance (5-80KB)
        + commitment_de_valor (1KB)
        + histórico_de_transferências (grows linearly)
  Total: 200KB - 1MB, multiple separate verifications
```

### The Solution

```
Proof-Carrying Token (PCT):
  Token = A SINGLE cryptographic object that simultaneously proves:
    1. It was legitimately issued (threshold of signers)
    2. It has not been spent (nullifier commitment)
    3. The bearer is compliant (embedded anonymous credential)
    4. The value is valid (range proof)
    5. The last N transfers were valid (bounded recursive fold)
  Estimated total: 300-600KB, ONE verification
```

**What makes this possible**: LatticeFold+ (CRYPTO 2025, Dan Boneh & Binyi Chen) - the first recursive folding scheme over lattices with performance comparable to HyperNova. Allows compressing cumulative proofs into constant size (up to a bound). Published in 2025 - nobody has applied it to ecash yet.

**Alternative if LatticeFold+ is insufficient**: Holography Accumulation (ePrint 2026/538, March 2026) - a framework that is NOT folding. Accumulates holographic polynomial verifications and collapses everything into a single polynomial evaluation. Genuinely different from Nova/LatticeFold.

### Real Sizes (Technical Honesty)

Published benchmarks indicate:
- LatticeFold+ for 2^20 constraints: ~17MB (without optimizations)
- With l2-norm optimizations: ~110-175KB per folding proof
- Isolated lattice range proofs: >90KB (vs <1KB for classic Bulletproofs)
- **LaZer Library** (IBM Research, CCS 2024, ePrint 2024/1846): 40-60KB for ring signature and anonymous credential proofs - the most practical existing tool
- Greyhound (lattice polynomial commitment): ~50KB proofs

For a complete PCT (blind sig + nullifier + credential + range + fold), the **honest estimate is 300-600KB**. This is 150-300x larger than a Zcash transaction (~2KB). It does not work for micropayments - it works for medium/high value transfers where privacy and PQ security justify the overhead.

### Bounded Recursion (Transfer Limit per Fold)

Kothapalli (CMU PhD, 2024) demonstrated that IVC soundness is proven only for logarithmic recursion depth. At polynomial depth, guarantees degrade. This means PCTs **cannot circulate indefinitely** with constant size.

**Solution**: bound on recursion depth. Each PCT allows up to N transfers (e.g., 20-50) before requiring **renewal** (re-fold from zero on the network). This naturally aligns with the offline wear-out mechanism: the hash chain and the recursion bound converge at the same point - after N transfers, the token MUST go online.

### Why This Is New

- Nobody has applied LatticeFold+ to ecash
- Nobody has created tokens that carry compliance credentials inside the fold
- Nobody has made ecash with constant size (bounded) per transfer via recursive folding
- Nobody has combined all of this with post-quantum

It is more accurate to call this an **unprecedented application of recursive proof composition to ecash** than a "new primitive" - technical honesty is important.

### Prior Art: Related Work

Geoffrey Goodell's group (UCL) published work that partially overlaps with the PCT concept:

- **Self-Validating Tokens** (arXiv:2409.01958, Sep 2024): tokens that carry proof of their own validity via ZK, with burn-and-mint and reissuance. Accepted at FC 2025 Workshops.
- **Sark / USO Architecture** (arXiv:2512.20775, Dec 2025): "Unforgeable, Stateful, Oblivious" assets without a global ledger. Closest architectural reference to PCT.
- **COME Protocol** (arXiv:2501.10419, Jan 2025): extension for compliant and oblivious transfers.

**Specter Differentiation vs Sark/USO**:

| Aspect | Sark/USO (Goodell) | Specter (PCT) |
|---|---|---|
| Post-quantum | ❌ | ✅ (native lattice-based) |
| Constant size | ❌ (grows linearly) | ✅ (bounded recursive fold) |
| Compliance embedded in token | ❌ | ✅ (anonymous credential inside the fold) |
| Offline with economic guarantees | ❌ | ✅ (VDF + bonds + blame) |
| Decentralization | Partial (crash-fault tolerant) | ✅ (BFT threshold) |

Goodell is prior art and a natural ally, not a competitor. Should be cited explicitly. Potential for collaboration.

---

## The Confirmed Gap: What Does Not Exist

After exhaustive research of papers, projects, and prototypes published up to April 2026, we confirm that **no system exists that combines**:

1. Decentralized issuance (threshold blind signatures)
2. Native post-quantum resistance (lattice-based)
3. Total privacy without anonymity budgets
4. Verifiable compliance without surveillance
5. Offline transferability with economic guarantees
6. Constant size per transfer (bounded)
7. Functional implementation with open source code

The individual pieces exist in separate papers. The combination does not exist.

### Comparative Table (Corrected and Expanded)

| System | Decentralized | PQ | Offline | Privacy | Private Compliance | Transferable | Constant Size |
|---|---|---|---|---|---|---|---|
| Bitcoin | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | N/A |
| Monero | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | N/A |
| Zcash | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | N/A |
| Cashu | ❌ (mint) | ❌ | ❌ | ✅ | ❌ | ❌ | N/A |
| Fedimint | Partial | ❌ | Partial | ✅ | ❌ | ❌ | N/A |
| UTT | ✅ | ❌ | ❌ | ❌ (budgets) | ❌ | ✅ | N/A |
| Privacy Pools | ✅ | ❌ | ❌ | Partial | Partial (funds) | N/A | N/A |
| Sark/USO | Partial | ❌ | ❌ | ✅ | Partial | ✅ | ❌ (linear) |
| **Specter** | **✅** | **✅** | **⚠️ Partial** | **✅** | **✅** | **✅** | **✅ (bounded)** |

**Note on Offline**: total offline without TEE and without double-spend is **mathematically impossible** (formalized in the Offline CBDC Trilemma, TU Munich, December 2025, arXiv:2512.10636). What Specter offers is "offline with accountability and economic guarantees" - better than any competitor, but not equivalent to physical cash.

---

## Technical Architecture

### Layer 1: Decentralized Issuance with Threshold Blind PCT

**Problem**: classic ecash (Chaum) requires a centralized mint that can be censored, hacked, or shut down.

**Solution**: threshold blind PCT issuance.

1. The user prepares a value commitment + anonymous identity credential
2. Blinds everything and sends it to k-of-n signing nodes
3. Each node signs its share without seeing the content (blind)
4. The user combines the partial signatures
5. Uses LatticeFold+ to **fold** the threshold signature + credential + range proof into a **single PCT**

Result: an object of ~300-600KB that proves everything in one verification.

**Cryptographic basis**:
- Lattice threshold blind signatures (Faller, Niot & Reichle, ePrint 2025/1566) - first scheme in the world, published in 2025. Overhead: 1.4-2.5x over non-threshold
- Improved lattice blind signatures (Jeudy & Sanders, CRYPTO 2025, ePrint 2024/1289) - 36KB/signature, with GitHub implementation
- Lattice blind signatures round-optimal (Agrawal et al., CCS 2023, ePrint 2023/077) - 20KB/signature
- LatticeFold+ recursive folding (Boneh & Chen, CRYPTO 2025, ePrint 2025/247) - 5-10x faster than v1
- **LaZer Library** (Lyubashevsky, Seiler & Steuer, IBM Research, CCS 2024, ePrint 2024/1846) - production-quality C library for lattice-based ZK proofs, 40-60KB proofs. Automatically generates proof systems from specified relations.
- Compact lattice threshold signatures (del Pino & Niot, PKC 2025, ePrint 2025/872) - threshold sig close to a single Dilithium size for T ≤ 8

**WARNING**: the BLAZE scheme (FC 2020) was broken. A cryptanalysis paper from February 2026 confirms: "all previously known lattice-based blind signature schemes contain subtle flaws." The papers above (CCS 2023 and CRYPTO 2025) are the correct state of the art.

**WARNING ON COMPOSITION**: the composition of 5 lattice-based primitives (blind signature + nullifier PRF + credential + range proof + folding) in a single system has NO unified security analysis. Each primitive uses slightly different assumptions (MSIS, MLWE, interactive variants). The "relaxed soundness" of lattice-based proofs (witnesses extracted in a wider domain than the honest prover's) accumulates slack at each layer. Formally analyzing this composition is a research contribution in itself.

### Layer 2: Transfer with Fold-on-Transfer

**Problem**: in classic ecash, transferring requires contacting the mint. In transferable ecash, each transfer adds data to the token (linear growth).

**Solution**: fold-on-transfer using LatticeFold+ with **bounded depth**.

When Alice transfers to Bob:
1. Alice reveals the PCT to Bob
2. Bob verifies locally (one verification)
3. Alice creates a transfer proof
4. Bob **folds** the transfer proof into the existing PCT

**Bounded constant size**: the PCT does not grow within the bound of N transfers (e.g., 20-50). After N transfers, the token must be renewed online (re-fold from zero). This is analogous to hash chain wear-out, and the two mechanisms converge: the hash chain and the recursion bound impose the same limit.

**Anti double-spend**: each token has a cryptographic "wear" (hash chain) - it can be transferred N times offline before needing renewal on the network. When it goes online, if double-spend occurred, the network detects and identifies the fraudster (blame protocol) but NOT the recipient.

**Direct prior art**:
- Goodell, Toliver & Nakib (UCL, 2024) - self-validating tokens with burn-and-mint and ZK-verified reissuance. The concept of self-validating tokens originated here; Specter differentiates through bounded folding (constant size) and native PQ
- Tewari & Hughes (2016) - transferable ecash without mint

### Layer 3: Compliance Without Surveillance

**Problem**: regulators require KYC/AML. Privacy coins ignore this and face bans. Privacy Pools prove that funds are not tainted, but do not prove that the USER is compliant.

**Solution**: anonymous credential embedded in the PCT that proves, without revealing identity:

- "The bearer passed KYC at an approved verifier"
- "The bearer is NOT on a sanctions list"
- "This transaction is within the regulatory limits of jurisdiction X"
- "The bearer is over 18 years old"

All verifiable by anyone, without learning ANYTHING about the bearer.

**Cryptographic basis (phased approach)**:

**Phase 1-2 (prototype on curves)**: **OpenAC** (ePrint 2026/251, Feb 2026, Ethereum PSE Lab) - anonymous credentials without trusted setup, compatible with eIDAS 2.0, proof presentation in **0.129 seconds on mobile**, compatible with Verifiable Credentials standards. Solves the BBS# risk without needing pairings.

**Phase 3 (PQ migration)**: two options:
- Cloudflare prototype of PQ anonymous credentials (October 2025): 85-175KB per credential. Functional but large.
- Lattice-based anonymous credentials with batch verification (ScienceDirect, 2025) + **SIS-with-Hints tight reductions** (ePrint 2026/291, Feb 2026) - reduces credential size by 4x over previous constructions (Bootle et al., CRYPTO 2023)
- **Fallback**: if no PQ credential is practical, keep OpenAC on curves for the compliance layer and protect only the other layers with PQ. The compliance credential is the part with the lowest quantum risk because it is renewable (unlike long-duration signatures).

**Why this is the killer feature**:
- For regulators: verifiable compliance without mass surveillance
- For users: zero privacy sacrificed
- For industry: solves the Privacy-Compliance Paradox that has blocked adoption for 10 years
- Timing: eIDAS 2.0 mandatory in the EU in September 2026; regulators NEED this

References:
- Privacy Pools (0xbow) - live on Ethereum mainnet (March 2025), $6M volume, 1500+ users
- zkMe - decentralized zkKYC, integrated with TON and multiple DeFi
- a16z paper - "Privacy-Protecting Regulatory Solutions Using ZKPs"
- Projected decentralized identity market: $103B by 2034

### Layer 4: Offline with Economic Guarantees

**Problem**: total offline without TEE and without double-spend is mathematically impossible (Trilemma formalized, TU Munich, December 2025, arXiv:2512.10636).

**Solution**: hybrid model with 3 levels of protection:

**Level 1 - Cryptographic Wear-Out (hash chain)**:
- Each PCT allows N offline transfers (e.g., 20-50, aligned with the recursion bound) before requiring online renewal
- Hash chain pre-committed at issuance
- Limits the potential damage from double-spend

**Level 2 - VDF Time-Lock**:
- Each PCT contains a Verifiable Delay Function that proves "this token was issued/renewed less than T hours ago"
- When the VDF "expires," the token loses offline value (renewable online)
- Based on the IETF draft from January 2026 (Verifiable Delay Tokens, Bakshi, C-DAC Pune)

**Level 3 - Reputation Bond (adapted Overdraft model)**:
- Users who want to spend offline stake collateral on the network
- Recipients verify the bond via proof included in the PCT (without revealing identity)
- If double-spend detected: bond confiscated + fraudster's identity revealed (blame)
- Based on: Overdraft (April 2025, Delft University, arXiv:2504.05143) - first system that replaces hardware trust with economic trust

**WARNING**: the combination of these 3 levels is unprecedented. The security of the composition has not been formally analyzed. This is a risk and simultaneously an opportunity for contribution.

### Layer 5: Network and Consensus

**Problem**: without a central mint, who decides which tokens are valid?

**Solution**: P2P network with lightweight BFT consensus:
- Nodes maintain a nullifier set (list of spent tokens)
- Consensus only for: issuance and registration of spent tokens
- Does not need a full blockchain - append-only log of nullifiers
- Nodes incentivized with minimal issuance/renewal fees

**Consensus**: HotStuff-2 (2023) or Bullshark (2022, DAG-based BFT) - more efficient versions than the original HotStuff.

**DKG (Distributed Key Generation)**: required for threshold keys. Lattice-based DKG protocol is an active research area - use classic DKG in the prototype phase and migrate later.

**Gossip-based nullifier propagation**: for eventually consistent double-spend detection in offline and mesh scenarios.

---

## Technical Stack (Corrected)

| Component | Technology | Notes |
|---|---|---|
| Main language | **Rust** | Performance, memory safety, crypto ecosystem |
| Blind signatures (lattice) | **oqs-rs** + custom implementation based on Jeudy/Sanders | github.com/latticeblindsignature/lattice-blind-signature |
| Blind signatures (prototype) | **curve25519-dalek** | For initial prototypes on elliptic curves |
| Folding/ZK proofs (PQ) | **LatticeFold+** or **LaZer Library** | NethermindEth/latticefold (Rust, research-grade); LaZer (C, production-quality, IBM) |
| Folding/ZK proofs (prototype) | **Nova/HyperNova** | For Phases 0-2 on curves |
| Credentials (prototype) | **OpenAC** | ePrint 2026/251, no trusted setup, eIDAS 2.0, 0.129s mobile |
| Credentials (PQ) | Cloudflare model + SIS-with-Hints | Fallback if PQ credentials are impractical |
| Signatures (network) | **HAWK-512** | NIST Round 2, 555 bytes, no floating point |
| Hash | **SHAKE-256** | NIST standard, quantum-resistant |
| P2P Network | **libp2p** | Mature, used by IPFS/Filecoin/Polkadot |
| Consensus | Custom implementation of **HotStuff-2** or **Bullshark** | |
| Serialization | **borsh** or **protobuf** | |
| Tests | **proptest** (property-based), **criterion** (benchmarks) | |

**What NOT to use**:
- ~~arkworks~~ - it is for elliptic curves, not lattices
- ~~bellman~~ - specific to Groth16/Zcash
- ~~lattigo~~ - Go, not Rust
- ~~BLAZE~~ - was broken
- ~~BBS+/BBS# on lattices~~ - does not exist; use OpenAC as bridge

---

## Essential Papers (Updated April 2026)

### Foundations (read first)
1. Chaum, "Blind Signatures for Untraceable Payments" (1983) - 4 pages, the basis of everything
2. Shamir, "How to Share a Secret" (1979) - threshold cryptography
3. Peikert, "A Decade of Lattice Cryptography" (2016) - lattice survey

### State of the Art in PQ Blind Signatures (read in Phase 0)
4. **Jeudy & Sanders, "Improved Lattice Blind Signatures from Recycled Entropy" (CRYPTO 2025, ePrint 2024/1289)** - 36KB/sig, with GitHub implementation
5. **Agrawal et al., "Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal" (CCS 2023, ePrint 2023/077)** - 20KB/sig, round-optimal
6. **Faller, Niot & Reichle, "Lattice-based Threshold Blind Signatures" (ePrint 2025/1566)** - first threshold blind PQ in the world
7. **Baldimtsi, Goyal & Yadav, "Batched & Non-interactive Blind Signatures from Lattices" (ePrint 2025/1771)** - cost independent of batch size

### Folding, PQ ZK Proofs and Alternatives (read in Phase 1-2)
8. **Boneh & Chen, "LatticeFold+" (CRYPTO 2025, ePrint 2025/247)** - PQ folding 5-10x faster than v1
9. **Boneh & Chen, "LatticeFold" (ASIACRYPT 2025, ePrint 2024/257)** - first lattice-based folding
10. **RoKoko (ePrint 2026/575)** - ~200KB proofs, 100x faster verification than Greyhound
11. **LaBRADOR (ePrint 2022/1341)** - 58KB proofs for R1CS, logarithmic verifier
12. **LaZer Library (ePrint 2024/1846, CCS 2024)** - practical lattice ZK library, IBM Research, 40-60KB proofs
13. **Holography Accumulation (ePrint 2026/538, March 2026)** - alternative to folding for proof composition; accumulates holographic polynomial verifications

### Ecash, Transfer and Prior Art (read in Phase 0-1)
14. Tomescu et al., "UTT: Decentralized Ecash with Accountable Privacy" (2022)
15. **Goodell et al., "Private Electronic Payments with Self-Custody and ZK-Verified Reissuance" (arXiv:2409.01958, 2024)** - self-validating tokens, direct prior art
16. **Sark: "Oblivious Integrity Without Global State" (arXiv:2512.20775, Dec 2025)** - USO architecture, architectural prior art
17. **COME: "Compliant, Obliviously Managed Electronic Transfers" (arXiv:2501.10419, Jan 2025)** - compliance + oblivious money
18. Cashu NUTs specification (cashu.space) - real protocol for studying modular design
19. Karantaidou et al., "Blind Multisignatures for Anonymous Tokens with Decentralized Issuance" (CCS 2024)

### Compliance, Credentials and Identity (read in Phase 2-3)
20. **OpenAC (ePrint 2026/251, Feb 2026)** - anonymous credentials without trusted setup, eIDAS 2.0, 0.129s mobile
21. **ePrint 2025/619, "Making BBS Anonymous Credentials eIDAS 2.0 Compliant"** - BBS# on curves (reference)
22. **SIS-with-Hints tight reductions (ePrint 2026/291, Feb 2026)** - reduces lattice-based credential size by 4x
23. **a16z, "Privacy-Protecting Regulatory Solutions Using ZKPs"** - conceptual framework
24. **Cloudflare, "Post-Quantum Anonymous Credentials" (October 2025)** - PQ prototype, 85-175KB

### Offline and Double-Spend (read in Phase 3)
25. **"Objectives and Design Principles in Offline Payments with CBDC" (arXiv:2512.10636, Dec 2025)** - formalizes the offline trilemma
26. **Overdraft (arXiv:2504.05143, April 2025)** - reputation-weighted loan networks
27. **IETF Verifiable Delay Token draft (January 2026)** - VDFs for tokens with proof of time

### Recursion and Soundness (read in Phase 1)
28. **Kothapalli, "A Theory of Composition for Proofs of Knowledge" (CMU-CS-24-126, 2024)** - soundness limits in IVC recursion
29. **Collaborative IVC (ePrint 2026/410, March 2026)** - multi-prover IVC with constant communication

### Threshold Signatures and Aggregation (read in Phase 3)
30. **del Pino & Niot, "A Compact Lattice-Based Threshold Signature" (PKC 2025, ePrint 2025/872)** - threshold sig ≈ single Dilithium for T ≤ 8
31. **"Aggregating Falcon Signatures with LaBRADOR" (ePrint 2024/311, CRYPTO 2024)** - PQ signature aggregation, proof ~58KB independent of the number of signatures
32. Lehmann et al., "Stronger Security for Threshold Blind Signatures" (EUROCRYPT 2025)

### Advanced / Group Actions and New Foundations (read in Phase 4+)
33. **Tanuki (ASIACRYPT 2025, ePrint 2025/1100)** - PQ blind signatures from group actions, 3.9KB (CSIDH)
34. **LIP-based Anonymous Signatures (ePrint 2026/436)** - blind signatures from the Lattice Isomorphism Problem, new mathematical foundation alternative to LWE/SIS

### Cryptanalysis and Attacks (read for awareness)
35. **"Cryptanalysis of Some Lattice-Based Blind Signatures" (February 2026)** - BLAZE broken
36. **"Revisiting Lattice-based Non-interactive Blind Signature" (ePrint 2025/1848)** - Zhang et al. broken
37. **"On the security of two blind signatures from code equivalence problems" (ePrint 2025/1883)** - LEAF broken

---

## Development Phases (30 Months)

### PHASE 0: Foundations (Months 1-3)
**Objective**: master the cryptographic building blocks + toy folding prototype

**Study**:
- Linear algebra over finite fields (essential for lattices)
- Lattices: LWE, SIS, NTRU - read Peikert 2016
- Blind signatures: Chaum 1983 → CCS 2023 → CRYPTO 2025 (Jeudy/Sanders)
- ZK proofs: Schnorr protocol → LatticeFold paper
- Threshold: Shamir secret sharing → threshold signatures
- Prior art: read Goodell et al. (2024) and Sark (2025) to understand the landscape

**Practice**:
- Week 1-2: Classic Pedersen commitment on curves (concept)
- Week 3-4: SIS-based commitment (lattices)
- Week 5-8: Schnorr blind signature in Rust (curve25519-dalek)
- Week 9-12: Clone and run LatticeFold (NethermindEth) + lattice blind signature (Jeudy/Sanders) + LaZer Library

**Deliverables**:
- GitHub repository with study implementations
- Technical notes documenting each primitive
- Toy example of folding

### PHASE 1: PCT Prototype on Curves (Months 3-7)
**Objective**: proof-of-concept of PCT using elliptic curves (faster to prototype)

**Tasks**:
1. Implement threshold blind signatures on curves
2. Implement fold-on-transfer using Nova/HyperNova (classic version) with recursion bound (N=20)
3. Implement anonymous credential with **OpenAC** (eIDAS 2.0 compatible)
4. Demonstrate: token issued → transferred N times → constant size → verifiable
5. Performance benchmarks

**Deliverables**:
- Rust library: `specter-core`
- CLI to issue, transfer, and verify PCTs
- **PREPRINT #1 on arXiv**: "Proof-Carrying Tokens: Constant-Size Transferable Ecash via Recursive Folding"

### PHASE 2: Compliance Layer + Offline Transfer (Months 7-12)
**Objective**: add private compliance and offline mechanism

**Tasks**:
1. Integrate OpenAC credential into the fold (curves version)
2. Implement hash chain for offline wear-out (aligned with recursion bound)
3. Implement blame protocol for double-spend detection
4. Implement nullifier set with ZK proof of non-inclusion
5. Simulate attack scenarios

**Deliverables**:
- Functional offline transfer (with limits)
- Verifiable compliance without revealing identity
- Network simulation with 10+ nodes
- **PREPRINT #2**: "Compliant Privacy: Anonymous Credentials in Bearer Tokens"

### PHASE 3: Post-Quantum Migration (Months 12-20)
**Objective**: replace EVERYTHING with lattice-based - this is the most difficult and longest phase

**WARNING**: this phase is estimated at 8 months because:
- Lattice blind signatures have "aborting" (protocol fails with significant probability)
- Sizes change radically (32B → 20-36KB per signature)
- Lattice-based ZK proofs are an active research area without mature implementations (except LaZer)
- The composition of primitives requires security analysis (original contribution)

**Tasks**:
1. Replace ECDSA with Dilithium/HAWK for network signatures
2. Replace Pedersen commitments with lattice commitments (SIS-based)
3. Replace blind signatures with Jeudy/Sanders or CCS 2023
4. Replace classic fold with LatticeFold+ (or LaZer + LaBRADOR as alternative)
5. Adapt credentials to PQ (Cloudflare model + SIS-with-Hints for 4x size reduction)
6. Benchmark PQ overhead vs classic
7. Security analysis of the composition (reduction to LWE/SIS/Module-SIS)

**Deliverables**:
- Complete PQ version of the protocol
- Comparison: classic vs PQ (sizes, times, failure rates)
- **SUBMISSION to CCS or IEEE S&P**

### PHASE 4: Advanced Offline + VDF + Bonds (Months 20-24)
**Objective**: offline model with economic guarantees

**Tasks**:
1. Implement VDF time-locks in PCTs
2. Implement reputation bond staking
3. Implement bond verification inside the PCT (without revealing identity)
4. Game-theoretic analysis of the incentive model
5. Simulation of double-spend scenarios with different parameters

**Deliverables**:
- Offline model with 3 levels of protection
- Formal analysis of incentives
- **PREPRINT #3**: "Offline Ecash Beyond TEE: Economic Guarantees with Cryptographic Blame"

### PHASE 5: P2P Network and Complete System (Months 24-28)
**Objective**: functional decentralized system

**Tasks**:
1. Implement P2P protocol (libp2p)
2. Implement BFT consensus (HotStuff-2 or Bullshark)
3. Implement DKG for threshold keys
4. Implement incentive mechanism for nodes
5. Testnet with distributed nodes
6. Complete CLI wallet

**Deliverables**:
- Functional testnet
- CLI wallet
- Modular protocol specification (Cashu NUTs style - numbered specs, independently implementable)

### PHASE 6: Publication and Launch (Months 28-30)
**Objective**: impact

**Tasks**:
1. Write main formal paper (target: CRYPTO or EUROCRYPT)
2. Formal security self-audit + community invitation
3. Launch open source code (MIT or Apache 2.0 license)
4. Publish protocol specification
5. Present at conference (Real World Crypto, Financial Cryptography)

**Deliverables**:
- Paper submitted to tier-1 conference
- Public repository with complete documentation
- Project website with spec

---

## Visual Timeline

```
2026
Jun-Aug  ████ PHASE 0: Foundations + toy folding + read prior art
Sep-Jan  █████ PHASE 1: PCT on curves + OpenAC → PREPRINT #1

2027
Feb-Jun  █████ PHASE 2: Compliance + offline → PREPRINT #2
Jul-Feb  ████████ PHASE 3: Full PQ migration → SUBMISSION CCS/S&P

2028
Mar-Jun  ████ PHASE 4: VDF + bonds + advanced offline → PREPRINT #3
Jul-Oct  ████ PHASE 5: P2P network + testnet + modular spec
Nov-Dec  ██ PHASE 6: Main paper + launch

Total: ~30 months
```

**Incremental publication strategy**: preprint every ~5 months. Plant the flag early. Makes it impossible to be scooped silently.

---

## Publishable Papers (5 Potential)

| # | Title | Target | Phase |
|---|---|---|---|
| 1 | "Proof-Carrying Tokens: Constant-Size Transferable Ecash via Recursive Folding" | ACM CCS | 1 |
| 2 | "Compliant Privacy: Anonymous Credentials Folded into Bearer Tokens" | IEEE S&P | 2 |
| 3 | "Post-Quantum Ecash at Scale: A LatticeFold+ Recursive Construction" | CRYPTO | 3 |
| 4 | "Offline Digital Cash with Economic Guarantees: Beyond the TEE Assumption" | Financial Crypto | 4 |
| 5 | "Specter: A Complete Decentralized PQ Ecash Protocol with Private Compliance" | EUROCRYPT | 6 |

---

## Funding and Institutional Paths

### Available Grants

**NGI TALER (NLnet Foundation)** - EUR 5K-50K per project
- Focus: "technology commons for privacy-friendly digital payments"
- Next deadline: **June 1, 2026**
- Specter as a complement to GNU Taler infrastructure
- Site: nlnet.nl/taler

**Horizon Europe PET Call** - EUR 3-4M per project
- The scope LITERALLY describes what we are building: "blockchain-based decentralized PETs... crypto-agile... post-quantum... anonymous credentials"
- 2025 call closed; successor calls expected in the 2026-2027 Work Programme (EUR 14B total)
- Site: cordis.europa.eu

**Ethereum Foundation Academic Grants** - up to $1.5M total per round
- Covers: PQ cryptography, ZK tooling, applied cryptography
- Requires open source output
- Site: esp.ethereum.foundation/academic-grants

**MSCA Postdoctoral Fellowships 2026**
- Opens April 2026, deadline September 2026
- Eligible topics include "post-quantum cryptography" and "privacy"
- 12-24 months with competitive salary
- Hostable at a European university (e.g., Granada)

### Institutional Paths

**OpenCBDC (MIT DCI)** - open issue #49 for blind signature integration. Contributing with the Specter approach would create institutional credibility.

**BIS Innovation Hub Swiss Centre** - where Project Tourbillon was done. Open to PQ privacy proposals for CBDC.

**GNU Taler** - Chaumian ecash operational in Switzerland since 2025. Specter could be positioned as the PQ layer for Taler infrastructure.

---

## Relevance for CBDCs

### What Central Banks Tested and Where They Failed

**Project Tourbillon** (BIS + SNB + David Chaum, 2023): built two ecash prototypes with blind signatures, including lattice-based PQ. **Result: throughput reduced 200x with PQ.** Proved the demand but demonstrated that PQ performance is the bottleneck.

**Project Leap Phase 2** (BIS, Dec 2025): tested PQ Dilithium on the TARGET2 system. **Result: signatures 12.9x larger** (3,293 bytes vs 256), latency increased significantly.

**ECB Digital Euro** (October 2025): chose **pseudonymization** instead of cryptographic privacy. No blind signatures, no ZKPs. Institutional privacy (access control), not mathematical.

### Where Specter Fits

If Specter demonstrates better PQ performance than Tourbillon (even 10x better would be notable), the system automatically enters the radar of the CBDC research community. LatticeFold+ recursive compression is exactly the type of optimization that could close the PQ performance gap.

The **BIS quantum-readiness roadmap** (July 2025, BIS Papers 158) establishes:
- RSA deprecated by 2030, prohibited by 2035
- PQ migrations underway in the late 2020s
- Specter would be mature (2028-2029) exactly when migrations begin

---

## Design Principles

Based on the analysis of projects that became references (Zcash, Tor, Signal, Cashu, Let's Encrypt, WireGuard), the principles to maximize impact:

1. **Simplicity above all.** The spec should be readable by a competent developer in 1-2 hours. Cashu won over Fedimint by being simpler. WireGuard won over OpenVPN with 4K lines vs 100K.

2. **Modular spec.** Inspired by Cashu NUTs and Bitcoin BIPs: numbered specs, each independently implementable. This allows multiple developers to create implementations, creating an ecosystem instead of a monolith.

3. **Publish incrementally.** Preprints every 5 months + public code from day 1. Establish priority and create a feedback loop.

4. **Say NO.** Do not add speculative features. Do not try to solve all problems. PCT + compliance + PQ + bounded offline is ambitious enough. Each additional feature dilutes focus.

5. **Framing as infrastructure, not product.** "Private and secure digital money protocol" - Tor model. Research + open source code, not a service.

---

## Risks and Mitigations

### Risk 1: Lattice blind signatures may be too inefficient
**Probability**: Medium
**Mitigation**: start with elliptic curves (Phases 0-2). If lattices are impractical, publish classic version + PQ feasibility analysis. Paper publishable in any case.

### Risk 2: Composition of 5 lattice-based primitives without unified analysis
**Probability**: High - NOBODY has done this analysis
**Mitigation**: this risk is simultaneously the biggest opportunity. The composition security analysis IS an original contribution. Using LaZer Library (IBM) as a base reduces risk because LaZer has a more mature internal security analysis. Start with composition of 2 primitives and expand incrementally.

### Risk 3: Someone publishes something similar first
**Probability**: 20%
**Mitigation**: publish incrementally. Preprints every ~5 months. Code on GitHub from day 1. The Goodell group (UCL) is the closest - consider proactive contact for collaboration.

### Risk 4: Too much complexity for one person
**Probability**: High
**CRITICAL Mitigation**: find a co-author or advisor with expertise in lattice crypto. In Granada, look within the mathematics/cryptography department. Apply for MSCA fellowship or grant that provides funding for collaboration.

### Risk 5: LatticeFold+ is not mature enough
**Probability**: Medium - NethermindEth implementation is research-grade
**Mitigation**: LaZer Library (IBM) as alternative for individual proofs. Holography Accumulation (ePrint 2026/538) as alternative to folding if necessary. Contribute to existing implementations.

### Risk 6: Limited recursion depth degrades UX
**Probability**: Low-Medium
**Mitigation**: a bound of N=20-50 transfers is generous for real use. Online renewal can be automated (wallet does background renewal when it has connectivity). In practice, physical cash also "needs to go to the bank" periodically.

### Risk 7: 300-600KB tokens are too large for adoption
**Probability**: Medium
**Mitigation**: position for medium/high value transfers, not micropayments. 300KB is viable for mobile (a smartphone photo is 3-5MB). The trend of lattice-based proof size reduction is consistent (2026 papers already show significant improvements).

### Risk 8: Legal
**Probability**: Low
**Mitigation**: publish as academic research. Do not operate a service. Tor model. The compliance layer is an argument in favor.

---

## Honest Assessment

### Realistic Scores

| Criterion | Score | Justification |
|---|---|---|
| Innovation | **8/10** | Unprecedented application of brand-new primitives; prior art exists (Sark) but without PQ/folding/compliance |
| Academic impact | **8/10** | 3-5 tier-1 papers realistic with strong execution |
| Industrial impact | **7/10** | Real need; 300-600KB tokens limit use; CBDC path increases potential |
| "Shaking the community" | **7/10** | Goodell's prior art shows the community already thinks about this; Specter would be the definitive PQ version |
| Probability of becoming a reference | **15-25%** | Real, not guaranteed. CBDC path and European funding increase chances vs previous assessment |
| Risk of failure | **25%** | Reduced vs previous (30%) by the discovery of LaZer, OpenAC, and Holography Accumulation as fallbacks |
| Career impact | **9/10** | Even in the pessimistic scenario, elite portfolio |

### Scenarios

| Scenario | Probability | Outcome |
|---|---|---|
| 2-3 papers, open source code, strong thesis | **50%** | Solid academic career, recognition in the PQ community |
| Someone publishes first, but your code has value | **15%** | Publishable as independent implementation |
| Becomes a real reference ("the PQ ecash") | **15-25%** | Conference invitations, funding, research position |
| Specter benchmarks surpass Tourbillon → CBDC interest | **10-15%** | Institutional funding, collaboration with BIS/ECB |
| Technical failure (primitives do not compose) | **10%** | Publishable as negative result + feasibility analysis |

### Why It Is Worth It
- In the absolute worst scenario: 1 paper + rare expertise in lattice crypto
- In the median scenario (50%): 2-3 tier-1 papers + elite portfolio
- In the good scenario (15-25%): reference that defines a subarea
- In the excellent scenario (10-15%): institutional relevance (CBDCs, BIS)
- **There is no project with a better risk/reward ratio to invest 30 months in**

---

## First 7 Days

**Day 1**: Read Chaum 1983 (4 pages). Install Rust. Read the abstract and introduction of LatticeFold+ (ePrint 2025/247).

**Day 2**: Read Shamir 1979 (6 pages). Implement Shamir Secret Sharing in Rust.

**Day 3**: Read the CCS 2023 paper (Agrawal et al.) - "Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal." Clone the Jeudy/Sanders repo (github.com/latticeblindsignature/lattice-blind-signature).

**Day 4**: Read the Cashu spec (cashu.space/specs) - study the modular design of the NUTs. Read Goodell et al. 2024 (arXiv:2409.01958) - understand prior art of self-validating tokens.

**Day 5**: Read Tanuki (ASIACRYPT 2025) - introduction + tables. Implement classic Schnorr blind signature in Rust (curve25519-dalek).

**Day 6**: Clone LatticeFold (github.com/NethermindEth/latticefold). Compile, run examples. Explore LaZer Library (ePrint 2024/1846).

**Day 7**: Create `specter-protocol` repository. Write README with honest vision. Publish study implementations. Apply to NGI TALER (deadline June 1, 2026) if timing allows.

---

## Competitive Context (April 2026)

### Relevant PQ Projects (None is Private Ecash)
- **Algorand**: first PQ transaction on mainnet (Falcon-1024, Nov 2025) - transparent, no privacy
- **Bitcoin BIP-360**: SHRIMPS hash-based PQ signatures (~2.5KB) - on testnet, no privacy
- **QRL**: migrating to SPHINCS+ - no privacy
- **Zcash**: PQ roadmap published, but admits proofs explode 1000x in Halo 2

### Privacy Projects (None is PQ)
- **Aztec Alpha** (March 2026): first private L2 on Ethereum - 1 TPS, not PQ
- **Namada** (December 2024): MASP multi-asset - not PQ
- **Privacy Pools** (March 2025): compliance without surveillance - not PQ, not ecash
- **Cashu/Fedimint**: functional ecash - centralized/federated, not PQ

### Direct Prior Art (None is PQ + Folding + Compliance)
- **Sark/USO** (Goodell, UCL, Dec 2025): self-validating tokens without ledger - not PQ, size grows linearly
- **COME Protocol** (Goodell, UCL, Jan 2025): oblivious compliance - not PQ, no folding

### CBDC Projects with Privacy (None is PQ + Practical)
- **Project Tourbillon** (BIS + SNB): tested PQ blind signatures, 200x throughput reduction
- **GNU Taler**: Chaumian ecash operational, not PQ
- **Digital Euro** (ECB): pseudonymization, not cryptographic privacy

### Specter's Position
Specter would be the **first system in the world** to combine PQ + privacy + compliance + decentralization + bounded constant size. Prior art exists (Sark/USO) but without PQ, folding, or embedded compliance. The differentiation is clear and verifiable.

---

## Acronyms and Glossary

- **PCT**: Proof-Carrying Token - the core innovation
- **PQ**: Post-Quantum - resistant to quantum computers
- **LWE**: Learning With Errors - hard problem in lattices
- **SIS**: Short Integer Solution - hard problem in lattices
- **MSIS/MLWE**: Module-SIS/Module-LWE - modular variants (base of Dilithium/Kyber)
- **BFT**: Byzantine Fault Tolerant - consensus that tolerates malicious nodes
- **DKG**: Distributed Key Generation - key generation among multiple nodes
- **VDF**: Verifiable Delay Function - proof of passage of time
- **IVC**: Incrementally Verifiable Computation - recursive verifiable computation
- **MASP**: Multi-Asset Shielded Pool - private multi-asset pool
- **ASP**: Association Set Provider - compliance list provider
- **eIDAS**: Electronic Identification, Authentication and Trust Services - EU regulation
- **USO**: Unforgeable, Stateful, Oblivious - Goodell's model for digital assets
- **OpenAC**: Open Anonymous Credentials - anonymous credentials without trusted setup (Ethereum PSE Lab)
- **LaZer**: Lattice-based Zero-knowledge - practical library from IBM Research
