use curve25519_dalek::{RistrettoPoint, Scalar};

/// A signer's keypair for blind Schnorr signatures.
#[derive(Clone, Debug)]
pub struct SignerKeypair {
    /// Secret signing key.
    pub secret: Scalar,
    /// Public verification key (secret * G).
    pub public: RistrettoPoint,
}

/// A blind Schnorr signature.
///
/// The signer produces this without knowing the message.
/// The verifier can verify it against the signer's public key and the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlindSignature {
    /// Response scalar.
    pub s: Scalar,
    /// Challenge scalar (as seen by the verifier, after unblinding).
    pub e: Scalar,
}
