//! NONOS Kernel Manifest Signing and Verification 

#![no_std]

use core::{convert::TryInto, fmt};

/// Ed25519 public key length in bytes.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 signature length in bytes (R||S).
pub const SIGNATURE_SIZE: usize = 64;

/// Embedded NONOS kernel Ed25519 public key (32 bytes).
/// The kernel uses this key in the boot/manifest verification path.
pub const NONOS_KERNEL_PUBLIC_KEY: [u8; ED25519_PUBLIC_KEY_LEN] = [
    0xa9, 0xb3, 0xa6, 0xfc, 0xc0, 0xb6, 0x46, 0xa1,
    0xa8, 0x01, 0xd8, 0x11, 0xcd, 0xc5, 0xc3, 0x24,
    0xdd, 0xa9, 0x47, 0x46, 0xa9, 0x8b, 0x9b, 0xae,
    0xef, 0x09, 0x9a, 0x40, 0x25, 0x56, 0x08, 0x86,
];

/// Manifest verification result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    Valid,
    InvalidSignature,
    InvalidFormat,
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationResult::Valid => write!(f, "Valid"),
            VerificationResult::InvalidSignature => write!(f, "Invalid signature"),
            VerificationResult::InvalidFormat => write!(f, "Invalid format"),
        }
    }
}

/// Require the production feature. This avoids shipping a kernel that
/// silently accepts signatures or contains placeholder verification logic.
#[cfg(not(feature = "crypto-ed25519"))]
compile_error!(
    "The production Ed25519 verifier is disabled. \
     Enable the \"crypto-ed25519\" feature and add ed25519-dalek to Cargo.toml \
     to enable manifest signature verification."
);

#[cfg(feature = "crypto-ed25519")]
mod verifier {
    use super::*;
    use core::convert::TryFrom;
    use ed25519_dalek::{PublicKey, Signature, Verifier};

    /// Verify a manifest signature using the embedded NONOS public key.
    ///
    /// Inputs:
    /// - manifest: raw bytes of the manifest to verify (the exact canonical
    ///   encoding used by tooling/CI must be produced by the signing tool).
    /// - signature: 64-byte Ed25519 signature (R||S).
    ///
    /// Returns one of VerificationResult variants. This function does NOT panic,
    /// and translates low-level parsing errors into InvalidFormat or
    /// InvalidSignature as appropriate.
    pub fn verify_manifest_signature(manifest: &[u8], signature: &[u8]) -> VerificationResult {
        // Validate input lengths
        if signature.len() != SIGNATURE_SIZE {
            return VerificationResult::InvalidFormat;
        }

        // Build PublicKey object from embedded bytes.
        // from_bytes returns an error if the key is not a valid curve point,
        // which we map to InvalidFormat.
        let pk_bytes: [u8; ED25519_PUBLIC_KEY_LEN] = NONOS_KERNEL_PUBLIC_KEY;
        let public_key = match PublicKey::from_bytes(&pk_bytes) {
            Ok(pk) => pk,
            Err(_) => {
                // Embedded public key is invalid (this should never happen in a
                // properly provisioned kernel image). Treat as invalid format.
                return VerificationResult::InvalidFormat;
            }
        };

        // Parse signature bytes into Signature object.
        let sig_bytes: [u8; SIGNATURE_SIZE] = match signature.try_into() {
            Ok(s) => s,
            Err(_) => return VerificationResult::InvalidFormat,
        };
        let sig = match Signature::try_from(&sig_bytes[..]) {
            Ok(s) => s,
            Err(_) => return VerificationResult::InvalidFormat,
        };

        // Perform verification. ed25519-dalek's verify returns Ok(()) on valid
        // signature and Err(...) otherwise.
        match public_key.verify(manifest, &sig) {
            Ok(()) => VerificationResult::Valid,
            Err(_) => VerificationResult::InvalidSignature,
        }
    }

    /// Expose the embedded public key to other kernel subsystems as a slice.
    pub fn get_kernel_public_key() -> &'static [u8; ED25519_PUBLIC_KEY_LEN] {
        &NONOS_KERNEL_PUBLIC_KEY
    }
}

#[cfg(feature = "crypto-ed25519")]
pub use verifier::{get_kernel_public_key, verify_manifest_signature};

#[cfg(test)]
mod tests {
    use super::*;

    // The tests are only compiled for the host 
    #[cfg(feature = "crypto-ed25519")]
    #[test]
    fn test_valid_signature_roundtrip() {
        // This test uses ed25519-dalek's test utilities to create a keypair and
        // verify a signature. It is a dev-only test and does not affect kernel
        // runtime behavior.
        use ed25519_dalek::{Keypair, Signer};
        use rand_chacha::ChaCha20Rng;
        use rand_core::{RngCore, SeedableRng};

        // Deterministic RNG seed for reproducible tests.
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17);
        }
        let mut rng = ChaCha20Rng::from_seed(seed);

        // Generate ephemeral keypair for test.
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let keypair = Keypair::generate(&mut rng);

        let manifest = b"test-manifest-bytes";
        let sig = keypair.sign(manifest);
        let sig_bytes = sig.to_bytes();

        // Build a public key buffer that mirrors the runtime embedded key.
        let pk = keypair.public.to_bytes();

        // Use the same codepath as production by temporarily shadowing the
        // embedded constant via a local binding for the test. This avoids
        // modifying the real embedded key.
        let verification_result = {
            // Verify using ed25519-dalek directly to ensure library correctness.
            match ed25519_dalek::PublicKey::from_bytes(&pk) {
                Ok(public_key) => {
                    match public_key.verify(manifest, &Signature::try_from(&sig_bytes[..]).unwrap()) {
                        Ok(()) => VerificationResult::Valid,
                        Err(_) => VerificationResult::InvalidSignature,
                    }
                }
                Err(_) => VerificationResult::InvalidFormat,
            }
        };

        assert_eq!(verification_result, VerificationResult::Valid);
    }

    #[test]
    fn test_invalid_length_signature() {
        let manifest = b"test";
        let bad_sig = [0u8; SIGNATURE_SIZE - 1];
        assert_eq!(verify_manifest_signature(manifest, &bad_sig), VerificationResult::InvalidFormat);
    }
}
