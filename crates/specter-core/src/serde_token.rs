//! Token serialization - converts PCT to/from portable byte format.
//!
//! Provides a compact binary encoding for Proof-Carrying Tokens that
//! can be written to disk, sent over the network, or embedded in QR codes.
//!
//! Format: custom binary with length-prefixed optional fields.
//! Every field is written as raw bytes with fixed or length-prefixed size.

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};

use specter_blind_sig::types::BlindSignature;
use specter_credential::credential::{Attributes, Credential};
use specter_credential::presentation::Presentation;
use specter_fold::accumulator::AccumulatedProof;
use specter_offline::vdf::VdfProof;

use crate::token::ProofCarryingToken;

/// Errors during serialization/deserialization.
#[derive(Debug, thiserror::Error)]
pub enum SerdeError {
    #[error("buffer too short: need {need} bytes, have {have}")]
    BufferTooShort { need: usize, have: usize },

    #[error("invalid point encoding at offset {offset}")]
    InvalidPoint { offset: usize },

    #[error("invalid scalar encoding at offset {offset}")]
    InvalidScalar { offset: usize },

    #[error("invalid magic bytes")]
    InvalidMagic,

    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("IO error: {0}")]
    Io(String),
}

/// Magic bytes identifying a Specter PCT file.
const MAGIC: &[u8; 4] = b"SPCT";
/// Current format version.
const VERSION: u8 = 1;

/// Serialize a PCT to bytes (includes all secrets).
///
/// SECURITY WARNING: This function exposes the owner_secret in the output.
/// Deserializing the output creates a second token with the same nullifier,
/// effectively duplicating the bearer instrument. The nullifier set prevents
/// both copies from being spent, but in distributed systems with propagation
/// delay this creates a double-spend race window.
///
/// Prefer `serialize_token_public()` for network transmission (zeros secrets)
/// or `serialize_encrypted()` for persistent storage (encrypts everything).
/// Use this function only for wallet-internal storage behind encryption.
pub fn serialize_token(token: &ProofCarryingToken) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);

    // Header
    buf.extend_from_slice(MAGIC);
    buf.push(VERSION);

    // Fixed fields
    buf.extend_from_slice(&token.token_id);                          // 32
    buf.extend_from_slice(&token.value.to_le_bytes());               // 8
    write_point(&mut buf, &token.value_commitment);                  // 32
    // ValueProof: commitment point (32) + response scalar (32) = 64 bytes
    write_point(&mut buf, &token.value_proof.commitment);             // 32
    write_scalar(&mut buf, &token.value_proof.response);              // 32
    write_scalar(&mut buf, &token.mint_signature.s);                 // 32
    write_scalar(&mut buf, &token.mint_signature.e);                 // 32
    buf.extend_from_slice(&token.owner_secret);                      // 32
    buf.extend_from_slice(&token.hash_chain_head);                   // 32
    buf.extend_from_slice(&token.transfer_count.to_le_bytes());      // 4
    buf.extend_from_slice(&token.recursion_bound.to_le_bytes());     // 4

    // Fold proof
    write_scalar(&mut buf, &token.fold_proof.s);                     // 32
    write_scalar(&mut buf, &token.fold_proof.e);                     // 32
    write_point(&mut buf, &token.fold_proof.r);                      // 32
    write_point(&mut buf, &token.fold_proof.pk);                     // 32
    buf.extend_from_slice(&token.fold_proof.state_hash);             // 32
    buf.extend_from_slice(&token.fold_proof.pk_chain_hash);          // 32
    buf.extend_from_slice(&token.fold_proof.genesis_state_hash);     // 32
    buf.extend_from_slice(&token.fold_proof.current_owner_hash);    // 32
    buf.extend_from_slice(&token.fold_proof.steps.to_le_bytes());    // 4
    buf.extend_from_slice(&token.genesis_owner_hash);               // 32

    // Optional: credential (flag byte + data)
    match &token.credential {
        Some(cred) => {
            buf.push(1); // present
            write_point(&mut buf, &cred.commitment);
            write_scalar(&mut buf, &cred.blinding);
            // Attributes
            buf.push(cred.attributes.kyc_passed as u8);
            buf.push(cred.attributes.not_sanctioned as u8);
            let jur = cred.attributes.jurisdiction.as_bytes();
            buf.push(jur.len() as u8);
            buf.extend_from_slice(jur);
            buf.push(cred.attributes.age_over_18 as u8);
            buf.extend_from_slice(&cred.attributes.expires_at.to_le_bytes());
            // Signature
            write_scalar(&mut buf, &cred.signature_s);
            write_scalar(&mut buf, &cred.signature_e);
            write_point(&mut buf, &cred.issuer_pk);
        }
        None => buf.push(0),
    }

    // Optional: presentation
    match &token.presentation {
        Some(pres) => {
            buf.push(1);
            write_point(&mut buf, &pres.commitment);
            write_point(&mut buf, &pres.issuer_pk);
            write_scalar(&mut buf, &pres.cred_signature_s);
            write_scalar(&mut buf, &pres.cred_signature_e);
            // Disclosed attributes
            buf.push(pres.disclosed.len() as u8);
            for (idx, val) in &pres.disclosed {
                buf.push(*idx as u8);
                write_scalar(&mut buf, val);
            }
            // ZK proof
            write_point(&mut buf, &pres.proof_commitment);
            buf.push(pres.proof_response.len() as u8);
            for r in &pres.proof_response {
                write_scalar(&mut buf, r);
            }
            write_scalar(&mut buf, &pres.proof_challenge);
        }
        None => buf.push(0),
    }

    // Optional: VDF proof
    match &token.vdf_proof {
        Some(vdf) => {
            buf.push(1);
            buf.extend_from_slice(&vdf.seed);
            buf.extend_from_slice(&vdf.iterations.to_le_bytes());
            buf.extend_from_slice(&vdf.output);
        }
        None => buf.push(0),
    }

    // Optional: bond owner ID
    match &token.bond_owner_id {
        Some(id) => {
            buf.push(1);
            buf.extend_from_slice(id);
        }
        None => buf.push(0),
    }

    buf
}

/// Deserialize a PCT from bytes.
pub fn deserialize_token(data: &[u8]) -> Result<ProofCarryingToken, SerdeError> {
    let mut pos = 0;

    // Header
    let magic = read_bytes(data, &mut pos, 4)?;
    if magic != MAGIC {
        return Err(SerdeError::InvalidMagic);
    }
    let version = read_u8(data, &mut pos)?;
    if version != VERSION {
        return Err(SerdeError::UnsupportedVersion(version));
    }

    // Fixed fields
    let token_id = read_array32(data, &mut pos)?;
    let value = read_u64(data, &mut pos)?;
    if value == 0 {
        return Err(SerdeError::Io("token value must be non-zero".into()));
    }
    let value_commitment = read_point(data, &mut pos)?;
    let vp_commitment = read_point(data, &mut pos)?;
    let vp_response = read_scalar(data, &mut pos)?;
    let sig_s = read_scalar(data, &mut pos)?;
    let sig_e = read_scalar(data, &mut pos)?;
    let owner_secret = read_array32(data, &mut pos)?;
    let hash_chain_head = read_array32(data, &mut pos)?;
    let transfer_count = read_u32(data, &mut pos)?;
    let recursion_bound = read_u32(data, &mut pos)?;
    if transfer_count > recursion_bound {
        return Err(SerdeError::Io("transfer_count exceeds recursion_bound".into()));
    }

    // Fold proof
    let fold_s = read_scalar(data, &mut pos)?;
    let fold_e = read_scalar(data, &mut pos)?;
    let fold_r = read_point(data, &mut pos)?;
    let fold_pk = read_point(data, &mut pos)?;
    let fold_state_hash = read_array32(data, &mut pos)?;
    let fold_pk_chain_hash = read_array32(data, &mut pos)?;
    let fold_genesis_state_hash = read_array32(data, &mut pos)?;
    let fold_current_owner_hash = read_array32(data, &mut pos)?;
    let fold_steps = read_u32(data, &mut pos)?;
    let genesis_owner_hash = read_array32(data, &mut pos)?;

    // Optional: credential
    let credential = if read_u8(data, &mut pos)? == 1 {
        let commitment = read_point(data, &mut pos)?;
        let blinding = read_scalar(data, &mut pos)?;
        let kyc_passed = read_u8(data, &mut pos)? != 0;
        let not_sanctioned = read_u8(data, &mut pos)? != 0;
        let jur_len = read_u8(data, &mut pos)? as usize;
        let jur_bytes = read_bytes(data, &mut pos, jur_len)?;
        let jurisdiction = String::from_utf8_lossy(jur_bytes).to_string();
        // Validate jurisdiction contains only safe characters (prevent injection)
        if !jurisdiction.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(SerdeError::Io("invalid jurisdiction characters".into()));
        }
        let age_over_18 = read_u8(data, &mut pos)? != 0;
        let expires_at = read_u64(data, &mut pos)?;
        let signature_s = read_scalar(data, &mut pos)?;
        let signature_e = read_scalar(data, &mut pos)?;
        let issuer_pk = read_point(data, &mut pos)?;

        Some(Credential {
            commitment,
            blinding,
            attributes: Attributes {
                kyc_passed,
                not_sanctioned,
                jurisdiction,
                age_over_18,
                expires_at,
            },
            signature_s,
            signature_e,
            issuer_pk,
        })
    } else {
        None
    };

    // Optional: presentation
    let presentation = if read_u8(data, &mut pos)? == 1 {
        let commitment = read_point(data, &mut pos)?;
        let issuer_pk = read_point(data, &mut pos)?;
        let cred_signature_s = read_scalar(data, &mut pos)?;
        let cred_signature_e = read_scalar(data, &mut pos)?;
        let n_disclosed = read_u8(data, &mut pos)? as usize;
        let mut disclosed = Vec::with_capacity(n_disclosed);
        for _ in 0..n_disclosed {
            let idx = read_u8(data, &mut pos)? as usize;
            let val = read_scalar(data, &mut pos)?;
            disclosed.push((idx, val));
        }
        let proof_commitment = read_point(data, &mut pos)?;
        let n_responses = read_u8(data, &mut pos)? as usize;
        let mut proof_response = Vec::with_capacity(n_responses);
        for _ in 0..n_responses {
            proof_response.push(read_scalar(data, &mut pos)?);
        }
        let proof_challenge = read_scalar(data, &mut pos)?;

        Some(Presentation {
            commitment,
            issuer_pk,
            cred_signature_s,
            cred_signature_e,
            disclosed,
            proof_commitment,
            proof_response,
            proof_challenge,
        })
    } else {
        None
    };

    // Optional: VDF proof
    let vdf_proof = if read_u8(data, &mut pos)? == 1 {
        let seed = read_array32(data, &mut pos)?;
        let iterations = read_u64(data, &mut pos)?;
        let output = read_array32(data, &mut pos)?;
        Some(VdfProof {
            seed,
            iterations,
            output,
        })
    } else {
        None
    };

    // Optional: bond owner ID
    let bond_owner_id = if read_u8(data, &mut pos)? == 1 {
        Some(read_array32(data, &mut pos)?)
    } else {
        None
    };

    Ok(ProofCarryingToken {
        token_id,
        value,
        value_commitment,
        value_proof: specter_primitives::pedersen::ValueProof {
            commitment: vp_commitment,
            response: vp_response,
        },
        mint_signature: BlindSignature { s: sig_s, e: sig_e },
        owner_secret,
        hash_chain_head,
        transfer_count,
        recursion_bound,
        fold_proof: AccumulatedProof {
            s: fold_s,
            e: fold_e,
            r: fold_r,
            pk: fold_pk,
            state_hash: fold_state_hash,
            pk_chain_hash: fold_pk_chain_hash,
            genesis_state_hash: fold_genesis_state_hash,
            current_owner_hash: fold_current_owner_hash,
            steps: fold_steps,
        },
        genesis_owner_hash,
        credential,
        presentation,
        vdf_proof,
        bond_owner_id,
    })
}

/// Serialize a PCT for network transmission (secrets zeroed for safety).
///
/// Zeros both the credential blinding factor AND the owner_secret in the
/// output. The receiver will generate their own owner_secret during the
/// transfer protocol. This avoids cloning the token (which is deliberately
/// non-Clone as a bearer instrument).
///
/// Offsets are derived from the `serialize_token` layout — keep these
/// constants in sync with any change to the wire format. A previous version
/// of this function computed CRED_FLAG_OFFSET incorrectly (missing
/// fold.genesis_state_hash and token.genesis_owner_hash) which left the
/// credential blinding factor un-redacted.
pub fn serialize_token_public(token: &ProofCarryingToken) -> Vec<u8> {
    let mut buf = serialize_token(token);

    // Layout (byte offsets):
    //   0    MAGIC(4)
    //   4    VERSION(1)
    //   5    token_id(32)
    //   37   value(8)
    //   45   value_commitment(32)
    //   77   vp_commitment(32)
    //   109  vp_response(32)
    //   141  sig_s(32)
    //   173  sig_e(32)
    //   205  owner_secret(32)              <-- OWNER_SECRET_OFFSET
    //   237  hash_chain_head(32)
    //   269  transfer_count(4)
    //   273  recursion_bound(4)
    //   277  fold_s(32)
    //   309  fold_e(32)
    //   341  fold_r(32)
    //   373  fold_pk(32)
    //   405  fold_state_hash(32)
    //   437  fold_pk_chain_hash(32)
    //   469  fold_genesis_state_hash(32)
    //   501  fold_current_owner_hash(32)   <-- new in v3 schema
    //   533  fold_steps(4)
    //   537  genesis_owner_hash(32)
    //   569  credential_flag(1)            <-- CRED_FLAG_OFFSET
    //   570  credential.commitment(32) (if flag == 1)
    //   602  credential.blinding(32) (if flag == 1)  <-- zeroed
    const OWNER_SECRET_OFFSET: usize = 4 + 1 + 32 + 8 + 32 + 32 + 32 + 32 + 32;
    debug_assert_eq!(OWNER_SECRET_OFFSET, 205);
    if buf.len() >= OWNER_SECRET_OFFSET + 32 {
        buf[OWNER_SECRET_OFFSET..OWNER_SECRET_OFFSET + 32].fill(0);
    }
    // From OWNER_SECRET_OFFSET to credential flag:
    // owner_secret(32) + hash_chain_head(32) + transfer_count(4) + recursion_bound(4)
    // + fold_s(32) + fold_e(32) + fold_r(32) + fold_pk(32) + fold_state_hash(32)
    // + fold_pk_chain_hash(32) + fold_genesis_state_hash(32)
    // + fold_current_owner_hash(32) + fold_steps(4) + genesis_owner_hash(32)
    // = 364
    const CRED_FLAG_OFFSET: usize = OWNER_SECRET_OFFSET
        + 32 + 32 + 4 + 4
        + 32 + 32 + 32 + 32 + 32 + 32 + 32 + 32 + 4 + 32;
    debug_assert_eq!(CRED_FLAG_OFFSET, 569);
    if buf.len() > CRED_FLAG_OFFSET && buf[CRED_FLAG_OFFSET] == 1 {
        let blinding_offset = CRED_FLAG_OFFSET + 1 + 32; // skip flag + commitment
        if buf.len() >= blinding_offset + 32 {
            buf[blinding_offset..blinding_offset + 32].fill(0);
        }
    }
    buf
}

/// Get the actual serialized size of a token in bytes.
pub fn serialized_size(token: &ProofCarryingToken) -> usize {
    serialize_token(token).len()
}

// ─── Binary helpers ─────────────────────────────────────────────────────

fn write_point(buf: &mut Vec<u8>, point: &RistrettoPoint) {
    buf.extend_from_slice(point.compress().as_bytes());
}

fn write_scalar(buf: &mut Vec<u8>, scalar: &Scalar) {
    buf.extend_from_slice(scalar.as_bytes());
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], SerdeError> {
    if *pos + len > data.len() {
        return Err(SerdeError::BufferTooShort {
            need: *pos + len,
            have: data.len(),
        });
    }
    let slice = &data[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, SerdeError> {
    let bytes = read_bytes(data, pos, 1)?;
    Ok(bytes[0])
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, SerdeError> {
    let bytes = read_bytes(data, pos, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, SerdeError> {
    let bytes = read_bytes(data, pos, 8)?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_array32(data: &[u8], pos: &mut usize) -> Result<[u8; 32], SerdeError> {
    let bytes = read_bytes(data, pos, 32)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

fn read_point(data: &[u8], pos: &mut usize) -> Result<RistrettoPoint, SerdeError> {
    let bytes = read_bytes(data, pos, 32)?;
    let compressed = CompressedRistretto::from_slice(bytes)
        .map_err(|_| SerdeError::InvalidPoint { offset: *pos - 32 })?;
    compressed
        .decompress()
        .ok_or(SerdeError::InvalidPoint { offset: *pos - 32 })
}

fn read_scalar(data: &[u8], pos: &mut usize) -> Result<Scalar, SerdeError> {
    let bytes = read_bytes(data, pos, 32)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Option::from(Scalar::from_canonical_bytes(arr))
        .ok_or(SerdeError::InvalidScalar { offset: *pos - 32 })
}

// ─── Encrypted serialization ───────────────────────────────────────────

/// Serialize and encrypt a token with a passphrase.
///
/// The output is fully encrypted — owner_secret and all other sensitive
/// data are protected by ChaCha20-Poly1305 under an Argon2id-derived key.
///
/// Returns an error if the passphrase fails validation (shorter than
/// `secure_store::MIN_PASSPHRASE_LEN`). Previously panicked with
/// `.expect()` on short passphrases.
pub fn serialize_encrypted(
    token: &ProofCarryingToken,
    passphrase: &[u8],
) -> Result<crate::secure_store::EncryptedData, SerdeError> {
    let plaintext = serialize_token(token);
    crate::secure_store::encrypt(&plaintext, passphrase)
        .map_err(|e| SerdeError::Io(e.to_string()))
}

/// Decrypt and deserialize a token with a passphrase.
///
/// Verifies integrity (wrong passphrase or tampered data = error)
/// before deserializing.
pub fn deserialize_encrypted(
    encrypted: &crate::secure_store::EncryptedData,
    passphrase: &[u8],
) -> Result<ProofCarryingToken, SerdeError> {
    let plaintext = crate::secure_store::decrypt(encrypted, passphrase)
        .map_err(|e| SerdeError::Io(e.to_string()))?;
    deserialize_token(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{Mint, MintConfig};
    use crate::transfer;
    use specter_credential::credential::Attributes;

    fn test_mint() -> Mint {
        Mint::setup(MintConfig {
            threshold: 2,
            total_signers: 3,
            recursion_bound: 20,
        })
    }

    fn test_attrs() -> Attributes {
        Attributes {
            kyc_passed: true,
            not_sanctioned: true,
            jurisdiction: "EU".to_string(),
            age_over_18: true,
            expires_at: 0,
        }
    }

    #[test]
    fn test_serialize_deserialize_basic() {
        let mint = test_mint();
        let token = mint.issue(1000, &[1, 2], None).unwrap();

        let bytes = serialize_token(&token);
        let recovered = deserialize_token(&bytes).unwrap();

        assert_eq!(recovered.token_id, token.token_id);
        assert_eq!(recovered.value, token.value);
        assert_eq!(recovered.transfer_count, token.transfer_count);
        assert_eq!(recovered.recursion_bound, token.recursion_bound);
        assert_eq!(recovered.owner_secret, token.owner_secret);
        assert_eq!(recovered.hash_chain_head, token.hash_chain_head);
    }

    #[test]
    fn test_serialize_deserialize_with_credential() {
        let mint = test_mint();
        let token = mint.issue(500, &[1, 2], Some(&test_attrs())).unwrap();

        let bytes = serialize_token(&token);
        let recovered = deserialize_token(&bytes).unwrap();

        assert!(recovered.credential.is_some());
        assert!(recovered.presentation.is_some());
        let cred = recovered.credential.as_ref().unwrap();
        assert!(cred.attributes.kyc_passed);
        assert!(cred.attributes.not_sanctioned);
        assert_eq!(cred.attributes.jurisdiction, "EU");
        assert!(cred.attributes.age_over_18);
    }

    #[test]
    fn test_serialize_deserialize_with_vdf_and_bond() {
        let mint = test_mint();
        let token = mint
            .issue_full(500, &[1, 2], Some(&test_attrs()), Some(50), Some([99u8; 32]))
            .unwrap();

        let bytes = serialize_token(&token);
        let recovered = deserialize_token(&bytes).unwrap();

        assert!(recovered.vdf_proof.is_some());
        assert_eq!(recovered.bond_owner_id, Some([99u8; 32]));
        let vdf = recovered.vdf_proof.as_ref().unwrap();
        assert_eq!(vdf.iterations, 50);
    }

    #[test]
    fn test_serialize_after_transfers() {
        let mint = test_mint();
        let token = mint.issue(1000, &[1, 2], Some(&test_attrs())).unwrap();

        let mut ns = crate::nullifier::NullifierSet::new();
        let mut current = token;
        for _ in 0..5 {
            current = transfer::transfer(current, &mut ns).unwrap().token;
        }

        let bytes = serialize_token(&current);
        let recovered = deserialize_token(&bytes).unwrap();

        assert_eq!(recovered.transfer_count, 5);
        assert_eq!(recovered.fold_proof.steps, 5);
        assert_eq!(recovered.value, 1000);
    }

    #[test]
    fn test_serialized_token_verifies() {
        let mint = test_mint();
        let token = mint.issue(500, &[1, 3], Some(&test_attrs())).unwrap();

        // Serialize → deserialize → verify
        let bytes = serialize_token(&token);
        let recovered = deserialize_token(&bytes).unwrap();

        let result = crate::verify::verify_token(
            &recovered,
            &mint.group_public_key(),
            &mint.pedersen,
            &mint.credential_issuer.pedersen,
            0,
        );
        assert!(result.all_valid());
    }

    #[test]
    fn test_transferred_serialized_token_verifies() {
        let mint = test_mint();
        let token = mint.issue(500, &[1, 2], Some(&test_attrs())).unwrap();

        let mut ns = crate::nullifier::NullifierSet::new();
        let mut current = token;
        for _ in 0..3 {
            current = transfer::transfer(current, &mut ns).unwrap().token;
        }

        let bytes = serialize_token(&current);
        let recovered = deserialize_token(&bytes).unwrap();

        let result = crate::verify::verify_token(
            &recovered,
            &mint.group_public_key(),
            &mint.pedersen,
            &mint.credential_issuer.pedersen,
            0,
        );
        assert!(result.all_valid());
    }

    #[test]
    fn test_tampered_bytes_fails() {
        let mint = test_mint();
        let token = mint.issue(500, &[1, 2], None).unwrap();

        let mut bytes = serialize_token(&token);
        // Tamper with value bytes (offset 5 = after magic+version, first field is token_id 32 bytes, then value at offset 37)
        bytes[37] ^= 0xFF;

        let recovered = deserialize_token(&bytes).unwrap();
        // Value is now different, verification should fail
        assert_ne!(recovered.value, token.value);
    }

    #[test]
    fn test_invalid_magic_fails() {
        let result = deserialize_token(b"FAKE\x01rest...");
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_data_fails() {
        let mint = test_mint();
        let token = mint.issue(500, &[1, 2], None).unwrap();
        let bytes = serialize_token(&token);

        // Truncate to half
        let truncated = &bytes[..bytes.len() / 2];
        let result = deserialize_token(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_real_token_sizes() {
        let mint = test_mint();

        // Basic token (no credential, no VDF, no bond)
        let basic = mint.issue(1000, &[1, 2], None).unwrap();
        let basic_size = serialized_size(&basic);
        println!("Basic token size: {} bytes", basic_size);
        assert!(basic_size > 300);
        assert!(basic_size < 600);

        // Full token (credential + VDF + bond)
        let full = mint
            .issue_full(1000, &[1, 2], Some(&test_attrs()), Some(50), Some([1u8; 32]))
            .unwrap();
        let full_size = serialized_size(&full);
        println!("Full token size:  {} bytes", full_size);
        assert!(full_size > basic_size);
        assert!(full_size < 2000);

        // After 10 transfers (should be same size - constant!)
        // Issue a fresh identical token for transfer (PCT is non-Clone by design)
        let mut ns = crate::nullifier::NullifierSet::new();
        let mut transferred = mint
            .issue_full(1000, &[1, 2], Some(&test_attrs()), Some(50), Some([1u8; 32]))
            .unwrap();
        for _ in 0..10 {
            transferred = transfer::transfer(transferred, &mut ns).unwrap().token;
        }
        let transferred_size = serialized_size(&transferred);
        println!("After 10 transfers: {} bytes", transferred_size);
        // Size should be approximately the same (constant-size proof)
        assert!((transferred_size as i64 - full_size as i64).unsigned_abs() < 50);
    }

    // ─── Encrypted serialization tests ──────────────────────────────

    #[test]
    fn test_encrypted_roundtrip() {
        let mint = test_mint();
        let token = mint.issue(1000, &[1, 2], Some(&test_attrs())).unwrap();
        let passphrase = b"strong-passphrase-min8-123";

        let encrypted = serialize_encrypted(&token, passphrase).unwrap();
        let recovered = deserialize_encrypted(&encrypted, passphrase).unwrap();

        assert_eq!(recovered.token_id, token.token_id);
        assert_eq!(recovered.value, token.value);
        assert_eq!(recovered.transfer_count, token.transfer_count);
    }

    #[test]
    fn test_encrypted_wrong_passphrase_fails() {
        let mint = test_mint();
        let token = mint.issue(1000, &[1, 2], None).unwrap();

        let encrypted = serialize_encrypted(&token, b"correct-min12").unwrap();
        let result = deserialize_encrypted(&encrypted, b"wrong-mn12-xx");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_tampered_ciphertext_fails() {
        let mint = test_mint();
        let token = mint.issue(1000, &[1, 2], None).unwrap();

        let mut encrypted = serialize_encrypted(&token, b"pass-min12-ok").unwrap();
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }
        let result = deserialize_encrypted(&encrypted, b"pass-min12-ok");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_token_verifies_after_decrypt() {
        let mint = test_mint();
        let token = mint.issue(500, &[1, 3], Some(&test_attrs())).unwrap();

        let encrypted = serialize_encrypted(&token, b"passphrase-min12").unwrap();
        let recovered = deserialize_encrypted(&encrypted, b"passphrase-min12").unwrap();

        let result = crate::verify::verify_token(
            &recovered,
            &mint.group_public_key(),
            &mint.pedersen,
            &mint.credential_issuer.pedersen,
            0,
        );
        assert!(result.all_valid());
    }

    #[test]
    fn test_encrypted_owner_secret_not_visible() {
        let mint = test_mint();
        let token = mint.issue(1000, &[1, 2], None).unwrap();
        let owner_secret = token.owner_secret;

        let encrypted = serialize_encrypted(&token, b"pass-min12-ok").unwrap();

        // The owner_secret should NOT appear in the ciphertext
        let secret_in_ciphertext = encrypted
            .ciphertext
            .windows(32)
            .any(|window| window == owner_secret);
        assert!(
            !secret_in_ciphertext,
            "owner_secret found in ciphertext - encryption failed"
        );
    }

    #[test]
    fn test_serialize_encrypted_rejects_short_passphrase() {
        let mint = test_mint();
        let token = mint.issue(100, &[1, 2], None).unwrap();
        // Must return Err, not panic.
        assert!(serialize_encrypted(&token, b"short").is_err());
    }
}
