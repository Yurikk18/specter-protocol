//! Unified VDF proof wrapper.
//!
//! Provides a single type that dispatches to either the legacy
//! hash-chain VDF or the production RSA-based VDF with Wesolowski
//! proofs. Existing code that produces `VdfProof` or `RsaVdfProof`
//! continues to work unchanged; this module wraps them for new
//! callsites that want a migration-friendly API.

use super::vdf::VdfProof;
use super::vdf_rsa::{RsaVdfParams, RsaVdfProof, VdfRsaError};
use num_bigint::BigUint;

/// Unified VDF proof that supports both the legacy hash-based VDF
/// and the production RSA-based VDF with Wesolowski proofs.
#[derive(Clone, Debug)]
pub enum UnifiedVdfProof {
    /// Legacy hash-chain VDF (deprecated, ASIC-accelerable).
    HashChain(VdfProof),
    /// RSA-2048 repeated-squaring VDF with Wesolowski proof.
    Rsa(RsaVdfProof),
}

/// Evaluate a unified VDF proof using the RSA path (production).
///
/// Creates an RSA VDF proof with the given parameters, input, and
/// iteration count. The result is wrapped in [`UnifiedVdfProof::Rsa`].
pub fn evaluate_unified(
    params: &RsaVdfParams,
    input: &BigUint,
    iterations: u64,
) -> Result<UnifiedVdfProof, VdfRsaError> {
    let proof = super::vdf_rsa::evaluate(params, input, iterations)?;
    Ok(UnifiedVdfProof::Rsa(proof))
}

/// Verify a unified VDF proof, dispatching to the correct verifier
/// based on the variant.
#[allow(deprecated)]
pub fn verify_unified(proof: &UnifiedVdfProof, rsa_params: &RsaVdfParams) -> bool {
    match proof {
        UnifiedVdfProof::HashChain(p) => super::vdf::verify(p),
        UnifiedVdfProof::Rsa(p) => super::vdf_rsa::verify(rsa_params, p),
    }
}

/// Check if a unified VDF proof has expired (fewer iterations than required).
pub fn is_expired_unified(proof: &UnifiedVdfProof, required_iterations: u64) -> bool {
    match proof {
        UnifiedVdfProof::HashChain(p) => p.iterations < required_iterations,
        UnifiedVdfProof::Rsa(p) => p.iterations < required_iterations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_rsa_evaluate_and_verify() {
        let params = RsaVdfParams::small_test();
        let input = BigUint::from(42u64);
        let proof = evaluate_unified(&params, &input, 100).unwrap();
        assert!(verify_unified(&proof, &params));
    }

    #[test]
    #[allow(deprecated)]
    fn test_unified_hash_chain_verify() {
        let seed = [7u8; 32];
        let hash_proof = super::super::vdf::evaluate(&seed, 50);
        let unified = UnifiedVdfProof::HashChain(hash_proof);
        let dummy_params = RsaVdfParams::small_test();
        assert!(verify_unified(&unified, &dummy_params));
    }

    #[test]
    fn test_is_expired_unified_rsa() {
        let params = RsaVdfParams::small_test();
        let input = BigUint::from(42u64);
        let proof = evaluate_unified(&params, &input, 50).unwrap();
        assert!(!is_expired_unified(&proof, 50));
        assert!(!is_expired_unified(&proof, 30));
        assert!(is_expired_unified(&proof, 100));
    }

    #[test]
    #[allow(deprecated)]
    fn test_is_expired_unified_hash_chain() {
        let seed = [1u8; 32];
        let hash_proof = super::super::vdf::evaluate(&seed, 50);
        let unified = UnifiedVdfProof::HashChain(hash_proof);
        assert!(!is_expired_unified(&unified, 50));
        assert!(is_expired_unified(&unified, 100));
    }
}
