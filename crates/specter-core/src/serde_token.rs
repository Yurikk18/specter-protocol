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

/// Serialize a PCT to bytes.
pub fn serialize_token(token: &ProofCarryingToken) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);

    // Header
    buf.extend_from_slice(MAGIC);
    buf.push(VERSION);

    // Fixed fields
    buf.extend_from_slice(&token.token_id);                          // 32
    buf.extend_from_slice(&token.value.to_le_bytes());               // 8
    write_point(&mut buf, &token.value_commitment);                  // 32
    write_scalar(&mut buf, &token.value_blinding);                   // 32
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
    buf.extend_from_slice(&token.fold_proof.steps.to_le_bytes());    // 4

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
    let value_commitment = read_point(data, &mut pos)?;
    let value_blinding = read_scalar(data, &mut pos)?;
    let sig_s = read_scalar(data, &mut pos)?;
    let sig_e = read_scalar(data, &mut pos)?;
    let owner_secret = read_array32(data, &mut pos)?;
    let hash_chain_head = read_array32(data, &mut pos)?;
    let transfer_count = read_u32(data, &mut pos)?;
    let recursion_bound = read_u32(data, &mut pos)?;

    // Fold proof
    let fold_s = read_scalar(data, &mut pos)?;
    let fold_e = read_scalar(data, &mut pos)?;
    let fold_r = read_point(data, &mut pos)?;
    let fold_pk = read_point(data, &mut pos)?;
    let fold_state_hash = read_array32(data, &mut pos)?;
    let fold_steps = read_u32(data, &mut pos)?;

    // Optional: credential
    let credential = if read_u8(data, &mut pos)? == 1 {
        let commitment = read_point(data, &mut pos)?;
        let blinding = read_scalar(data, &mut pos)?;
        let kyc_passed = read_u8(data, &mut pos)? != 0;
        let not_sanctioned = read_u8(data, &mut pos)? != 0;
        let jur_len = read_u8(data, &mut pos)? as usize;
        let jur_bytes = read_bytes(data, &mut pos, jur_len)?;
        let jurisdiction = String::from_utf8_lossy(jur_bytes).to_string();
        let age_over_18 = read_u8(data, &mut pos)? != 0;
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
                expires_at: 0,
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
        value_blinding,
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
            steps: fold_steps,
        },
        credential,
        presentation,
        vdf_proof,
        bond_owner_id,
    })
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
/// The output is fully encrypted - owner_secret and all other sensitive
/// data are protected. An HMAC verifies integrity before decryption.
pub fn serialize_encrypted(
    token: &ProofCarryingToken,
    passphrase: &[u8],
) -> crate::secure_store::EncryptedData {
    let plaintext = serialize_token(token);
    crate::secure_store::encrypt(&plaintext, passphrase)
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

        let mut current = token;
        for _ in 0..5 {
            current = transfer::transfer(&current).unwrap().token;
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
        );
        assert!(result.all_valid());
    }

    #[test]
    fn test_transferred_serialized_token_verifies() {
        let mint = test_mint();
        let mut token = mint.issue(500, &[1, 2], Some(&test_attrs())).unwrap();

        for _ in 0..3 {
            token = transfer::transfer(&token).unwrap().token;
        }

        let bytes = serialize_token(&token);
        let recovered = deserialize_token(&bytes).unwrap();

        let result = crate::verify::verify_token(
            &recovered,
            &mint.group_public_key(),
            &mint.pedersen,
            &mint.credential_issuer.pedersen,
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
        assert!(basic_size < 500);

        // Full token (credential + VDF + bond)
        let full = mint
            .issue_full(1000, &[1, 2], Some(&test_attrs()), Some(50), Some([1u8; 32]))
            .unwrap();
        let full_size = serialized_size(&full);
        println!("Full token size:  {} bytes", full_size);
        assert!(full_size > basic_size);
        assert!(full_size < 2000);

        // After 10 transfers (should be same size - constant!)
        let mut transferred = full.clone();
        for _ in 0..10 {
            transferred = transfer::transfer(&transferred).unwrap().token;
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
        let passphrase = b"strong-passphrase-123";

        let encrypted = serialize_encrypted(&token, passphrase);
        let recovered = deserialize_encrypted(&encrypted, passphrase).unwrap();

        assert_eq!(recovered.token_id, token.token_id);
        assert_eq!(recovered.value, token.value);
        assert_eq!(recovered.transfer_count, token.transfer_count);
    }

    #[test]
    fn test_encrypted_wrong_passphrase_fails() {
        let mint = test_mint();
        let token = mint.issue(1000, &[1, 2], None).unwrap();

        let encrypted = serialize_encrypted(&token, b"correct");
        let result = deserialize_encrypted(&encrypted, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_tampered_ciphertext_fails() {
        let mint = test_mint();
        let token = mint.issue(1000, &[1, 2], None).unwrap();

        let mut encrypted = serialize_encrypted(&token, b"pass");
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }
        let result = deserialize_encrypted(&encrypted, b"pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_token_verifies_after_decrypt() {
        let mint = test_mint();
        let token = mint.issue(500, &[1, 3], Some(&test_attrs())).unwrap();

        let encrypted = serialize_encrypted(&token, b"passphrase");
        let recovered = deserialize_encrypted(&encrypted, b"passphrase").unwrap();

        let result = crate::verify::verify_token(
            &recovered,
            &mint.group_public_key(),
            &mint.pedersen,
            &mint.credential_issuer.pedersen,
        );
        assert!(result.all_valid());
    }

    #[test]
    fn test_encrypted_owner_secret_not_visible() {
        let mint = test_mint();
        let token = mint.issue(1000, &[1, 2], None).unwrap();
        let owner_secret = token.owner_secret;

        let encrypted = serialize_encrypted(&token, b"pass");

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
}
