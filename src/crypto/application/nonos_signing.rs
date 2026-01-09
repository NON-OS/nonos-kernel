// NØNOS Operating System
// Copyright (C) 2024 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::{convert::TryInto, fmt};

pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const NONOS_KERNEL_PUBLIC_KEY: [u8; ED25519_PUBLIC_KEY_LEN] = [
    0xa9, 0xb3, 0xa6, 0xfc, 0xc0, 0xb6, 0x46, 0xa1,
    0xa8, 0x01, 0xd8, 0x11, 0xcd, 0xc5, 0xc3, 0x24,
    0xdd, 0xa9, 0x47, 0x46, 0xa9, 0x8b, 0x9b, 0xae,
    0xef, 0x09, 0x9a, 0x40, 0x25, 0x56, 0x08, 0x86,
];

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

#[cfg(not(any(feature = "crypto-ed25519-int", feature = "crypto-ed25519-dalek")))]
compile_error!(
    "The production Ed25519 verifier is disabled. \
     Enable the \"crypto-ed25519-int\" or \"crypto-ed25519-dalek\" feature \
     to enable manifest signature verification."
);

#[cfg(feature = "crypto-ed25519-int")]
mod verifier {
    use super::*;
    use crate::crypto::ed25519;
    pub fn verify_manifest_signature(manifest: &[u8], signature: &[u8]) -> VerificationResult {
        if signature.len() != SIGNATURE_SIZE {
            return VerificationResult::InvalidFormat;
        }

        let sig_bytes: [u8; SIGNATURE_SIZE] = match signature.try_into() {
            Ok(s) => s,
            Err(_) => return VerificationResult::InvalidFormat,
        };

        if ed25519::verify(&NONOS_KERNEL_PUBLIC_KEY, manifest, &sig_bytes) {
            VerificationResult::Valid
        } else {
            VerificationResult::InvalidSignature
        }
    }

    pub fn get_kernel_public_key() -> &'static [u8; ED25519_PUBLIC_KEY_LEN] {
        &NONOS_KERNEL_PUBLIC_KEY
    }
}

#[cfg(all(feature = "crypto-ed25519-dalek", not(feature = "crypto-ed25519-int")))]
mod verifier {
    use super::*;
    use core::convert::TryFrom;
    use ed25519_dalek::{PublicKey, Signature, Verifier};
    pub fn verify_manifest_signature(manifest: &[u8], signature: &[u8]) -> VerificationResult {
        if signature.len() != SIGNATURE_SIZE {
            return VerificationResult::InvalidFormat;
        }

        let pk_bytes: [u8; ED25519_PUBLIC_KEY_LEN] = NONOS_KERNEL_PUBLIC_KEY;
        let public_key = match PublicKey::from_bytes(&pk_bytes) {
            Ok(pk) => pk,
            Err(_) => {
                return VerificationResult::InvalidFormat;
            }
        };

        let sig_bytes: [u8; SIGNATURE_SIZE] = match signature.try_into() {
            Ok(s) => s,
            Err(_) => return VerificationResult::InvalidFormat,
        };
        let sig = match Signature::try_from(&sig_bytes[..]) {
            Ok(s) => s,
            Err(_) => return VerificationResult::InvalidFormat,
        };

        match public_key.verify(manifest, &sig) {
            Ok(()) => VerificationResult::Valid,
            Err(_) => VerificationResult::InvalidSignature,
        }
    }

    pub fn get_kernel_public_key() -> &'static [u8; ED25519_PUBLIC_KEY_LEN] {
        &NONOS_KERNEL_PUBLIC_KEY
    }
}

#[cfg(any(feature = "crypto-ed25519-int", feature = "crypto-ed25519-dalek"))]
pub use verifier::{get_kernel_public_key, verify_manifest_signature};

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(feature = "crypto-ed25519-int", feature = "crypto-ed25519-dalek"))]
    #[test]
    fn test_valid_signature_roundtrip() {
        use ed25519_dalek::{Keypair, Signer};
        use rand_chacha::ChaCha20Rng;
        use rand_core::{RngCore, SeedableRng};
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17);
        }
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let keypair = Keypair::generate(&mut rng);
        let manifest = b"test-manifest-bytes";
        let sig = keypair.sign(manifest);
        let sig_bytes = sig.to_bytes();
        let pk = keypair.public.to_bytes();
        let verification_result = {
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
