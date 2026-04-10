//! Token minting (issuance) via threshold blind signatures.

use curve25519_dalek::RistrettoPoint;

use specter_blind_sig::threshold::{self, SignerId, ThresholdKeyset};
use specter_credential::credential::Attributes;
use specter_credential::issuer::Issuer;
use specter_credential::presentation;
use specter_fold::accumulator::{self, TransferState};
use specter_primitives::pedersen::PedersenParams;
use specter_primitives::scalar_utils::{random_scalar, scalar_from_u64};

use crate::token::ProofCarryingToken;

/// Configuration for the mint.
pub struct MintConfig {
    pub threshold: usize,
    pub total_signers: usize,
    pub recursion_bound: u32,
}

/// The Mint: issues new Proof-Carrying Tokens.
pub struct Mint {
    pub keyset: ThresholdKeyset,
    pub pedersen: PedersenParams,
    pub credential_issuer: Issuer,
    pub recursion_bound: u32,
}

impl Mint {
    /// Set up a new mint with the given configuration.
    pub fn setup(config: MintConfig) -> Self {
        let keyset = threshold::dealer_keygen(config.threshold, config.total_signers);
        let pedersen = PedersenParams::new();
        let credential_issuer = Issuer::new();
        Self {
            keyset,
            pedersen,
            credential_issuer,
            recursion_bound: config.recursion_bound,
        }
    }

    /// Issue a new token with the given value and optional features.
    ///
    /// - `attributes`: compliance credential (KYC, sanctions, etc.)
    /// - `vdf_iterations`: if set, creates a VDF time-lock proof
    /// - `bond_owner_id`: if set, links the token to a reputation bond
    pub fn issue(
        &self,
        value: u64,
        signers: &[SignerId],
        attributes: Option<&Attributes>,
    ) -> Result<ProofCarryingToken, MintError> {
        self.issue_full(value, signers, attributes, None, None)
    }

    /// Issue with all optional features.
    pub fn issue_full(
        &self,
        value: u64,
        signers: &[SignerId],
        attributes: Option<&Attributes>,
        vdf_iterations: Option<u64>,
        bond_owner_id: Option<[u8; 32]>,
    ) -> Result<ProofCarryingToken, MintError> {
        if value == 0 {
            return Err(MintError::InvalidValue);
        }

        // Generate random token ID and owner secret
        let mut token_id = [0u8; 32];
        let mut owner_secret = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut token_id);
        rand::thread_rng().fill_bytes(&mut owner_secret);

        // Create Pedersen commitment to the value
        let value_scalar = scalar_from_u64(value);
        let blinding = random_scalar();
        let value_commitment = self.pedersen.commit(&value_scalar, &blinding);

        // Threshold blind sign
        let signed_msg = build_signed_message(&token_id, &value_commitment);
        let signature = threshold::threshold_blind_sign(&self.keyset, signers, &signed_msg)
            .map_err(|e| MintError::SigningFailed(e.to_string()))?;

        // Create initial fold proof
        let mut owner_hash = [0u8; 32];
        owner_hash.copy_from_slice(&specter_primitives::scalar_utils::hash_to_scalar(&owner_secret).as_bytes()[..32]);
        let genesis_state = TransferState {
            token_id,
            owner_hash,
            step: 0,
        };
        let fold_proof = accumulator::create_initial_proof(&genesis_state);

        // Issue compliance credential if attributes provided
        let credential = attributes.map(|attrs| self.credential_issuer.issue(attrs));

        // Create compliance presentation if credential exists
        let pres = credential.as_ref().map(|cred| {
            presentation::create_presentation(
                cred,
                &[presentation::ATTR_KYC_PASSED, presentation::ATTR_NOT_SANCTIONED],
                &self.credential_issuer.pedersen,
            )
        });

        // Hash chain genesis
        let hash_chain_head = crate::token::advance_hash_chain(&[0u8; 32], &token_id);

        // VDF time-lock (if requested)
        let vdf_proof = vdf_iterations.map(|iters| {
            let seed = specter_offline::vdf::create_seed(&token_id, 0);
            specter_offline::vdf::evaluate(&seed, iters)
        });

        Ok(ProofCarryingToken {
            token_id,
            value,
            value_commitment,
            value_blinding: blinding,
            mint_signature: signature,
            owner_secret,
            hash_chain_head,
            transfer_count: 0,
            recursion_bound: self.recursion_bound,
            fold_proof,
            credential,
            presentation: pres,
            vdf_proof,
            bond_owner_id,
        })
    }

    /// Get the group public key (used for verification).
    pub fn group_public_key(&self) -> RistrettoPoint {
        self.keyset.group_public
    }
}

/// Build the message that gets threshold-blind-signed.
pub fn build_signed_message(token_id: &[u8; 32], value_commitment: &RistrettoPoint) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(token_id);
    msg.extend_from_slice(value_commitment.compress().as_bytes());
    msg
}

/// Errors during minting.
#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("invalid value: token value must be > 0")]
    InvalidValue,
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_mint_without_credential() {
        let mint = test_mint();
        let token = mint.issue(1000, &[1, 2], None).unwrap();
        assert_eq!(token.value, 1000);
        assert!(token.credential.is_none());
        assert!(token.presentation.is_none());
        assert_eq!(token.fold_proof.steps, 0);
    }

    #[test]
    fn test_mint_with_credential() {
        let mint = test_mint();
        let attrs = test_attrs();
        let token = mint.issue(1000, &[1, 2], Some(&attrs)).unwrap();
        assert!(token.credential.is_some());
        assert!(token.presentation.is_some());
    }

    #[test]
    fn test_mint_verify_roundtrip() {
        let mint = test_mint();
        let token = mint.issue(500, &[1, 3], Some(&test_attrs())).unwrap();

        let result = crate::verify::verify_token(
            &token,
            &mint.group_public_key(),
            &mint.pedersen,
            &mint.credential_issuer.pedersen,
        );
        assert!(result.all_valid());
    }
}
