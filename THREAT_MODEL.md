# Specter Protocol — Threat Model

This document formalizes what Specter Protocol defends against, what it
does not, and the assumptions the proofs rest on. It is the canonical
reference for any security review of the codebase.

## System Summary

Specter Protocol is a Rust implementation of Proof-Carrying Tokens
(PCTs): bearer-instrument digital-cash tokens that a user can hold,
transfer to another user, and verify locally without trusting any
single party after issuance.

Each PCT carries:

1. A **threshold blind Schnorr signature** from the mint
2. A **Pedersen commitment** to the token's value
3. A **signed transfer chain** recording every prior owner (see
   `specter-fold::accumulator`)
4. A **selective-disclosure credential** (optional) proving the holder
   passed the issuer's compliance checks
5. A **VDF time-lock proof** (optional) — RSA-2048 Wesolowski or the
   deprecated hash-based prototype
6. A **reputation bond pointer** (optional) for offline spending

The **nullifier set** maintained by the network prevents double-spending
by recording `H(owner_secret || token_id)` of every spent token.

## Assets

| Asset                 | Confidentiality | Integrity | Availability |
| --------------------- | --------------- | --------- | ------------ |
| Token value           | public          | ✅        | ✅           |
| Token holder identity | **private**     | ✅        | ✅           |
| Transfer history      | **private**     | ✅        | ✅           |
| Wallet passphrase     | **private**     | ✅        | n/a          |
| Mint signing keys     | **private**     | ✅        | ✅           |
| Validator signing keys| **private**     | ✅        | ✅           |
| Credentials / attrs   | partial (via ZK)| ✅        | ✅           |

"Value = public" is a deliberate design choice. Specter does NOT
implement confidential transactions — the `value: u64` field is
plaintext in every token. If value privacy is ever added, Bulletproofs
or equivalent range proofs become mandatory (see section 13 of the
audit prompt for the negative-value attack that range proofs exist to
block).

## In-Scope Adversaries

### A1 — Network eavesdropper (passive)

**Capabilities:** reads all network traffic, cannot modify.

**Defenses:** SIGMA-I authenticated handshake (`specter-cli`) +
ChaCha20-Poly1305 session encryption. Gossip messages are Schnorr-
signed and verified against registered validator public keys.

### A2 — Active MitM on the client-to-receiver path

**Capabilities:** intercepts, modifies, drops, and replays messages
between two Specter CLI endpoints.

**Defenses:** SIGMA-I handshake pins the peer's long-term public key,
derived via out-of-band exchange (CLI arg). Any attempt to substitute
a different identity during the handshake fails peer verification.

### A3 — Malicious mint signer (up to threshold − 1)

**Capabilities:** controls up to `t − 1` of the `n` mint signers,
attempts to forge signatures, learn plaintext of signing requests,
or influence DKG to control the group key.

**Defenses:** Threshold Schnorr requires `t` participants to sign.
DKG uses Feldman VSS with Schnorr proofs-of-knowledge of each
participant's constant term (rogue-key defense, Gennaro et al. 1999).
Commitment-vector length is enforced to match `t` (Trail of Bits 2024
threshold-raising defense). Blind signatures preserve unlinkability
even against a dishonest subset of signers.

### A4 — Malicious token holder

**Capabilities:** owns a legitimate token, attempts to double-spend,
clone, forge value, forge credentials, or forge transfer history.

**Defenses:**

| Attempt                                  | Blocked by                                                  |
| ---------------------------------------- | ----------------------------------------------------------- |
| Spend the same token twice               | Atomic nullifier check-and-insert                           |
| Clone with swapped `owner_secret`        | `fold_proof.current_owner_pk()` check in `verify_token`     |
| Inflate value via `mint.split`           | Full re-verify of input token before burning the nullifier  |
| Submit a token with value outside u64    | Impossible at the type level                                |
| Forge a "negative" value (section 13)    | u64 type + plaintext value prevents wraparound to group ord |
| Forge transfer history at step > 0       | Signed transfer chain: every step is a Schnorr signature by the previous owner's signing key, anchored to the mint signature via `H(genesis_owner_pk)` |
| Renew an invalid token                   | `renew_token` runs full 6-check verify before publication   |

### A5 — Malicious validator / Byzantine consensus

**Capabilities:** controls up to `f < n/3` BFT validators, attempts to
cause double-commits, violate safety, or stall liveness.

**Defenses:** HotStuff-like commit requires 2f+1 Schnorr-signed votes
with view number bound into the signed message (anti-replay across
view changes). Leader equivocation is detected via `seen_proposals`
map. Block hash integrity is verified before commit.

### A6 — Offline / network-partitioned recipient

**Capabilities:** receives tokens while offline, cannot immediately
check the nullifier set.

**Defenses (defense-in-depth, not cryptographic guarantees):**
- VDF time-lock caps offline validity
- Reputation bonds cover potential double-spend losses
- Attestation chain exposes the sender's identity (v3 binds pubkey)
- Economic deterrence analysis in `specter-core::deterrence`

Note: **offline acceptance is always a trust-dependent operation.**
The protocol minimizes loss via slashing but cannot make offline
double-spend cryptographically impossible.

### A7 — Process-local memory scraper

**Capabilities:** reads the Specter process's heap/stack after crypto
operations, attempts to recover secrets from swap, core dumps, or
hibernation files.

**Defenses:**

- Every type holding a secret scalar implements `Drop` with explicit
  `zeroize()` (SignerKeypair, Issuer, Credential blinding, DkgParticipant,
  ValidatorKey, NodeIdentity, Share, Session nonces, etc.)
- `secure_store::decrypt` / `encrypt` zeroize the Argon2-derived key
  on both success and failure paths
- `deserialize_encrypted` zeroizes the decrypted plaintext Vec<u8>
- `random_scalar()` zeroizes the 64-byte CSPRNG intermediate buffer
- `specter-core::memory_guard` provides `LockedBytes` (mlock / VirtualLock
  + zeroize) and `disable_core_dumps()` called from CLI startup

### A8 — Adaptive-message attacker on the blind signer

**Capabilities:** opens multiple concurrent signing sessions, attempts
the ROS / Wagner / Benhamouda et al. 2021 attack on plain blind Schnorr.

**Defenses:** `RateLimitedSigner` enforces single-session serialization
in both single-threaded and multi-threaded deployments (8-thread
contention test locks in the invariant). For users who need
concurrency, `clause_blind` provides the Abe 2001 ROS-resistant
variant.

## Out of Scope

The following are explicitly NOT defended by the protocol as currently
implemented:

1. **Hardware-backed attackers with physical access.** Side-channel
   attacks that require oscilloscope / power analysis on the device are
   out of scope. Specter's constant-time audit covers algorithmic
   timing but not physical emanation.
2. **Compromised host OS.** If the kernel is rooted, mlock and core-dump
   disabling are defeated. Specter is not a TEE system.
3. **Confidential values.** Value is plaintext by design. If a future
   version adds confidentiality, Bulletproofs become mandatory.
4. **Long-term post-quantum security.** Ristretto255 / Schnorr /
   Pedersen fall to Shor's algorithm. Symmetric primitives
   (Argon2id, ChaCha20-Poly1305, SHAKE-256) remain PQ-sound. Migration
   path: hybrid with Dilithium + SPHINCS+ + Kyber.
5. **Catastrophic supply-chain compromise** of the Rust toolchain or
   curve25519-dalek / chacha20poly1305 upstream. We rely on RustSec
   monitoring (`cargo audit`) to catch CVEs.
6. **Network-layer Sybil / Eclipse attacks** beyond the BFT consensus
   layer. The `specter-net::gossip` layer requires all broadcasts to
   be Schnorr-signed by a validator, but a well-resourced attacker
   controlling `> n/3` validators can break consensus (standard BFT
   assumption).
7. **Trusted setup for Nova IVC.** The optional `nova` feature relies
   on pasta_curves parameters. Out of scope until someone enables Nova
   in production and explicitly vets the setup transcript.

## Assumptions

Security proofs rely on:

- **ECDLP** over Ristretto255 (Schnorr sigs, Pedersen commitments, SIGMA-I)
- **Random oracle model** (SHAKE-256 and SHA-512 for hash-to-scalar)
- **RSA assumption** (VDF time-locks via `vdf_rsa`)
- **`cargo-audit` advisory database** is current
- **Operator correctly configures** `RLIMIT_MEMLOCK`, disables core
  dumps on Unix, uses strong passphrases (>= 12 bytes, ideally
  passphrase-manager-generated)

## Attack Surface Summary

| Layer             | Primary defense                            | Test coverage                       |
| ----------------- | ------------------------------------------ | ----------------------------------- |
| Input parsing     | Magic bytes, length bounds, canonical scalar check | fuzz/ + `test_deserialize_*`    |
| Mint signing      | Threshold Schnorr + DKG PoK                | `dkg::tests::test_*`, mandatory_coverage |
| Token issue       | Value commitment + mint sig + owner pk hash anchor | mandatory_coverage              |
| Transfer          | Signed transfer chain + atomic nullifier   | transfer::tests + mandatory_coverage |
| Verify            | 6-check pipeline (sig/value/bound/chain/credential/VDF) | mandatory_coverage             |
| Wallet            | Argon2id 128MiB + ChaCha20-Poly1305 + mlock | wallet::tests + mandatory_coverage |
| Network handshake | SIGMA-I + peer pubkey pinning              | identity_tests                      |
| BFT consensus     | Signed view-bound votes + equivocation     | consensus::tests                    |
| Gossip            | Schnorr-signed broadcasts + replay rejection | gossip::tests                     |
| Attestation chain | v3 hash with sender pubkey                 | attestation::tests                  |

## Formal Verification Gaps

The following properties have test coverage but no machine-checked
proof:

- Value conservation across all `transfer` / `split` call paths
- `ConcurrentNullifierSet` linearizability under arbitrary schedules
- Fiat-Shamir completeness of every transcript in the system
- Blindness of the threshold signer against `t − 1` colluders

These are flagged for future formal verification with Hax / Creusot /
Kani once the crypto surface stabilizes.
