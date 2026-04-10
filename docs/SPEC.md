# Specter Protocol Specification v0.1

## Abstract

Specter is a decentralized digital cash protocol based on Proof-Carrying Tokens (PCT). Each token is a self-verifying bearer instrument that embeds cryptographic proofs of legitimate issuance, transfer history integrity, and regulatory compliance - all without revealing the holder's identity. Tokens maintain constant size regardless of transfer count via recursive proof folding.

## 1. Proof-Carrying Token (PCT)

A PCT is a single cryptographic object containing:

| Field | Size | Purpose |
|---|---|---|
| token_id | 32 B | Unique identifier |
| value | 8 B | Denomination |
| value_commitment | 32 B | Pedersen commitment hiding the value |
| value_blinding | 32 B | Opening factor (holder's secret) |
| mint_signature | 64 B | Threshold blind Schnorr signature |
| owner_secret | 32 B | Current holder's secret (for nullifier) |
| hash_chain_head | 32 B | Transfer history commitment |
| transfer_count | 4 B | Number of transfers |
| recursion_bound | 4 B | Maximum transfers before renewal |
| fold_proof | ~160 B | Accumulated proof (s, e, R, PK, state_hash) |
| credential | ~256 B | Anonymous compliance credential (optional) |
| presentation | ~512 B | Selective disclosure ZK proof (optional) |
| vdf_proof | ~72 B | Time-lock proof (optional) |
| bond_owner_id | 32 B | Bond backing reference (optional) |

**Total: 413 bytes (basic) / 1,039 bytes (full features)**

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

1. Sender reveals PCT to receiver
2. Receiver verifies: signature, value commitment, fold proof, credential, bounds
3. Sender creates a nullifier: `SHAKE-256(owner_secret || token_id)`
4. Receiver generates new owner_secret, advances hash chain, folds new proof
5. Nullifier is published to the network for double-spend detection

Token size remains constant - the fold proof absorbs each transfer without growing.

## 4. Verification

Six independent checks, all must pass:

1. **Signature**: Blind signature valid against group public key
2. **Value**: Pedersen commitment opens correctly
3. **Bound**: transfer_count <= recursion_bound
4. **Fold**: Schnorr equation `s*G == R + e*PK` holds
5. **Credential**: Selective disclosure presentation valid (if present)
6. **VDF**: Time-lock proof valid (if present)

## 5. Compliance

Anonymous credentials prove attributes without revealing identity:

- "Holder passed KYC" (without revealing who)
- "Holder is not sanctioned" (without revealing against which list)
- "Transaction is within jurisdictional limits" (without revealing amount)
- "Holder is over 18" (without revealing age)

Verifier learns ONLY the disclosed attribute values. Hidden attributes are protected by a ZK proof of knowledge.

## 6. Offline Payments

Three-layer protection for offline use:

1. **Hash chain wear-out**: Token allows N offline transfers before requiring online renewal
2. **VDF time-lock**: Token carries proof of when it was issued; expires after T time
3. **Reputation bonds**: Sender stakes collateral; double-spend = bond slashed + identity revealed

## 7. Consensus

Nullifier-only BFT consensus:

- Append-only log of spent nullifiers (not a full blockchain)
- HotStuff-2-inspired leader rotation with view change
- Quorum: 2f+1 out of 3f+1 validators
- Authenticated votes: Schnorr signatures verified against registered validator keys
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
| Authenticated consensus | Schnorr-signed votes |
| Encrypted storage | Argon2id + ChaCha20-Poly1305 |

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
| KDF | Argon2id (64 MB, 3 iterations) | Memory-hard |

## 10. Limitations

- **Not zero-knowledge**: The fold proof proves structural integrity but is not a zkSNARK. Nova IVC (feature-gated) provides true ZK on Linux/macOS.
- **Offline is partial**: Double-spend is detected when the token goes online, not prevented offline. This is a mathematical impossibility without TEE hardware.
- **Token size ~1 KB**: Larger than Cashu (~200 B) but carries much more (fold proof, credential, VDF).
- **No formal security proof**: The composition of primitives has not been formally analyzed. Each primitive is individually secure under standard assumptions.
