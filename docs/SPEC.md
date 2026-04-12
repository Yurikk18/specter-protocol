# Specter Protocol Specification v0.1

## Abstract

Specter is a decentralized digital cash protocol based on Proof-Carrying Tokens (PCT). Each token is a self-verifying bearer instrument that embeds cryptographic proofs of legitimate issuance, transfer history integrity, and regulatory compliance - all without revealing the holder's identity. Tokens maintain constant size regardless of transfer count via recursive proof folding.

## 1. Proof-Carrying Token (PCT)

A PCT is a single cryptographic object containing:

| Field | Size | Purpose |
|---|---|---|
| token_id | 32 B | Unique identifier (CSPRNG) |
| value | 8 B | Denomination (u64) |
| value_commitment | 32 B | Pedersen commitment hiding the value |
| value_proof | 64 B | ZK proof of value (commitment + response scalar) |
| mint_signature | 64 B | Threshold blind Schnorr signature |
| owner_secret | 32 B | Current holder's secret (for nullifier) |
| hash_chain_head | 32 B | Transfer history commitment |
| transfer_count | 4 B | Number of transfers |
| recursion_bound | 4 B | Maximum transfers before renewal |
| fold_proof | ~196 B | Accumulated proof (s, e, R, PK, state_hash, pk_chain_hash, steps) |
| credential | ~288 B | Anonymous compliance credential with 5 attributes (optional) |
| presentation | ~512 B | Selective disclosure ZK proof (optional) |
| vdf_proof | ~72 B | Time-lock proof (optional) |
| bond_owner_id | 32 B | Bond backing reference (optional) |

**Total: 413 bytes (basic) / 1,039 bytes (full features)**

The token is a **non-Clone** bearer instrument in Rust: `ProofCarryingToken` does not implement `Clone`, enforcing single-ownership via move semantics at the type system level.

## 2. Issuance

Tokens are issued via threshold blind signatures:

1. User commits to value: `C = v*G + r*H` (Pedersen)
2. User blinds the commitment and sends to k-of-n signers
3. Each signer produces a partial blind signature
4. User combines partials via Lagrange interpolation
5. User unblinds to obtain final signature
6. User creates initial fold proof (Schnorr over genesis state)

No individual signer knows the token content or the final signature.

## 3. Transfer

The `transfer()` function takes `ProofCarryingToken` by value (move semantics) — the caller surrenders ownership, preventing reuse at the type level.

1. Sender reveals PCT to receiver (via `serialize_token_public()` which zeros `owner_secret`)
2. Receiver verifies: signature, value commitment, fold proof, credential, bounds
3. Nullifier is computed: `SHAKE-256("specter-nullifier:" || owner_secret || token_id)`
4. Nullifier is atomically checked-and-inserted into the `NullifierSet` (double-spend = immediate rejection)
5. New owner_secret generated (CSPRNG), hash chain advanced, fold proof accumulated
6. Nullifier published to network via authenticated gossip for global double-spend detection

Token size remains constant — the fold proof absorbs each transfer without growing.

## 4. Verification

Six independent checks, all computed without early return (no short-circuit):

1. **Signature**: Blind signature valid against group public key
2. **Value**: ZK proof of value (Pedersen commitment verified via value_proof, no raw blinding factor needed)
3. **Bound**: transfer_count <= recursion_bound
4. **Fold**: Schnorr equation `s*G == R + e*PK` holds
5. **Credential**: Selective disclosure presentation valid (if present)
6. **VDF**: Time-lock proof valid (if present)

## 5. Compliance

Anonymous credentials prove attributes without revealing identity. Five attributes are committed in a Pedersen vector commitment, signed by the issuer:

1. **KYC passed** — "Holder passed KYC" (without revealing who)
2. **Not sanctioned** — "Holder is not on a sanctions list" (without revealing against which list)
3. **Jurisdiction** — "Transaction is within jurisdictional limits" (without revealing amount)
4. **Age over 18** — "Holder is over 18" (without revealing age)
5. **Expires at** — Credential expiry timestamp (cryptographically bound — cannot be modified post-issuance)

Verifier learns ONLY the disclosed attribute values. Hidden attributes are protected by a ZK proof of knowledge. Credentials can be revoked by commitment hash or by holder ID (covering all credentials for a given user).

## 6. Offline Payments

Three-layer protection for offline use:

1. **Hash chain wear-out**: Token allows N offline transfers before requiring online renewal
2. **VDF time-lock**: Token carries proof of when it was issued; expires after T time
3. **Reputation bonds**: Sender stakes collateral; double-spend = bond slashed + identity revealed

## 7. Consensus

Nullifier-only BFT consensus:

- Append-only log of spent nullifiers (not a full blockchain)
- HotStuff-2-inspired leader rotation with view change
- Quorum: 2f+1 out of 3f+1 validators (minimum 4 for fault tolerance; n<4 emits a warning)
- Authenticated votes: Schnorr signatures verified against registered validator keys
- View number included in vote signature to prevent cross-view replay
- Equivocation detection: conflicting proposals from the same leader at the same height
- Pending nullifiers stored in a HashSet with 100K cap (O(1) lookup, DoS-resistant)
- Forged, tampered, and duplicate votes are rejected

## 8. Security Properties

| Property | Mechanism |
|---|---|
| Unforgeability | Threshold blind signatures (t-of-n) |
| Privacy | Blinding factors hide token content from signers |
| Unlinkability | Different sessions produce different signatures on same message |
| Double-spend detection | Deterministic nullifiers via SHAKE-256 |
| Constant-size proof | Recursive Schnorr folding (bounded depth) |
| Memory safety | Zeroize secrets on drop |
| Authenticated consensus | Schnorr-signed votes with view replay protection |
| Authenticated gossip | Signed nullifier broadcasts |
| Non-Clone bearer tokens | Move semantics prevent value duplication |
| Encrypted storage | Argon2id (128 MB) + ChaCha20-Poly1305 |
| Crash-safe persistence | fsync on nullifier writes |

## 9. Cryptographic Primitives

| Primitive | Construction | Security |
|---|---|---|
| Commitment | Pedersen over Ristretto255 | Binding + Hiding under DL |
| Blind signature | Schnorr blind (3-move) | Unforgeability under DL |
| Threshold | Shamir + Lagrange over Ristretto | t-of-n security |
| Fold proof | Schnorr over Fiat-Shamir transcript | Soundness under DL |
| Credential | Schnorr signature over Pedersen vector | Selective disclosure |
| VDF (prototype) | Iterated SHA-256 | Sequential by hash chain |
| VDF (production) | RSA repeated squaring + Wesolowski | Sequential under factoring |
| Nullifier | SHAKE-256(secret \|\| token_id) | Collision-resistant |
| Encryption | ChaCha20-Poly1305 | IND-CCA2 |
| KDF | Argon2id (128 MB, 4 iterations) | Memory-hard |

## 10. Symmetric Blind Tokens (SBT)

An alternative issuance path using threshold DH-OPRF (specter-sbt):

1. Client picks payload, derives `(s, r) = HKDF(client_secret, payload)`
2. Commits `C = g*s + h*r` (Pedersen with NUMS generators)
3. Blinds `B = H2C(C) * alpha` (alpha random), sends B to mint
4. Each trustee i computes `B_i = B * k_i` + Chaum-Pedersen DDH proof
5. Client verifies DDH proofs, Lagrange-combines to get `B*k`, unblinds to `T = P*k`
6. Client builds TokenProof (Schnorr PoK of commitment opening, bound to aggregate key Y)
7. Token = `(C, T, proof, session_id)`, nullifier = `SbtNullifier(SHAKE-256("SPECTER-SBT-NULL-v1/" || T))`

**Spend-time verification** (threshold, no pairings):
- Each validator re-evaluates `T'_i = H2C(C) * k_i` + DDH proof under a fresh spend_session_id
- Combine to get `T'`, check `T' == T` in constant time

**Security**: unlinkable (random alpha), unforgeable (Gap-CDH), double-spend resistant (deterministic nullifier).

## 10b. AMD SEV-SNP Attestation (specter-tee)

Hardware attestation for validators in confidential VMs:

1. Validator requests report: `Firmware::get_ext_report(user_data = SHA-512(pubkey))`
2. AMD PSP signs report body with VCEK (ECDSA-P384)
3. Host returns report + cert table (ARK, ASK, VCEK)
4. Peer verifies: chain self-check → report signature → user_data binding → TCB policy

**TCB Policy** enforces: minimum firmware version (component-wise), measurement allow-list (SHA-384), max VMPL.

**Platform independence**: `PortableSnpVerifier` uses pure-Rust `crypto_nossl` backend, works on Windows/macOS/Linux.

## 11. Specter Security Framework

### Deterrence Theorem
For any adversary with bond B > token value V: E[profit] = V - B - reputation_cost < 0. Double-spending is economically irrational. This is formally stronger than TEE-based prevention, which relies on hardware trust assumptions that have been broken (Spectre, Plundervolt, SGAxe).

### Social Attestation Chain
Each offline transfer creates a witness. Conflicting attestation chains (same token, different receivers) provide cryptographic blame proof. Detection happens between offline devices via chain comparison.

### Lazy PQ Migration
PQ protection on mint signature only (long-lived). Classical crypto for ephemeral fold proofs. PQ overhead paid once at issuance.

## 11. Trade-offs

- **Token size ~1 KB**: Larger than Cashu (~65 B) because it carries fold proof, credential, and VDF that Cashu tokens do not have.
- **Offline requires bond**: Economic deterrence requires the spender to have staked collateral. Without bond, the deterrence guarantee does not hold.
- **Nova IVC requires Linux/macOS**: The pasta-msm assembly in Nova does not link on Windows. The hash-based accumulator works on all platforms as a fallback.
