use curve25519_dalek::Scalar;
use rand_core::OsRng;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Generate a cryptographically random scalar.
pub fn random_scalar() -> Scalar {
    let mut scalar_bytes = [0u8; 64];
    let mut rng = OsRng;
    use rand_core::RngCore;
    rng.fill_bytes(&mut scalar_bytes);
    Scalar::from_bytes_mod_order_wide(&scalar_bytes)
}

/// Convert a u64 value to a scalar.
pub fn scalar_from_u64(v: u64) -> Scalar {
    Scalar::from(v)
}

/// Hash arbitrary data to a scalar using SHAKE-256.
///
/// Uses domain separation to produce a deterministic scalar from input bytes.
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Shake256::default();
    hasher.update(b"specter-hash-to-scalar:");
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut wide = [0u8; 64];
    reader.read(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_scalar_nonzero() {
        let s = random_scalar();
        assert_ne!(s, Scalar::ZERO);
    }

    #[test]
    fn test_scalar_from_u64() {
        let s = scalar_from_u64(42);
        assert_ne!(s, Scalar::ZERO);
    }

    #[test]
    fn test_hash_to_scalar_deterministic() {
        let a = hash_to_scalar(b"hello");
        let b = hash_to_scalar(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn test_hash_to_scalar_different_inputs() {
        let a = hash_to_scalar(b"hello");
        let b = hash_to_scalar(b"world");
        assert_ne!(a, b);
    }
}
