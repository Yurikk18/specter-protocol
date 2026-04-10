use curve25519_dalek::{RistrettoPoint, Scalar};

/// A signer's keypair for blind Schnorr signatures.
#[derive(Clone)]
pub struct SignerKeypair {
    /// Secret signing key (private - never exposed).
    secret: Scalar,
    /// Public verification key (secret * G).
    pub public: RistrettoPoint,
}

impl SignerKeypair {
    /// Create a keypair from a secret and public key.
    pub(crate) fn from_parts(secret: Scalar, public: RistrettoPoint) -> Self {
        Self { secret, public }
    }

    /// Access the secret key (crate-internal only).
    #[allow(dead_code)]
    pub(crate) fn secret(&self) -> &Scalar {
        &self.secret
    }
}

impl std::fmt::Debug for SignerKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerKeypair")
            .field("secret", &"[REDACTED]")
            .field("public", &self.public)
            .finish()
    }
}

impl Drop for SignerKeypair {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

/// A blind Schnorr signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlindSignature {
    /// Response scalar.
    pub s: Scalar,
    /// Challenge scalar (as seen by the verifier, after unblinding).
    pub e: Scalar,
}
