// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use crate::algs::traits::{KeyPair, Signer, Verifier};
use crate::error::SignError;

use super::{ffi, keygen, verify};

pub struct MlDsa65;

impl Signer for MlDsa65 {
    fn keygen_from_seed(seed: &[u8]) -> Result<KeyPair, SignError> {
        keygen::from_seed(seed)
    }

    fn keygen_random() -> Result<KeyPair, SignError> {
        keygen::random()
    }

    fn sign(seed: &[u8], msg: &[u8]) -> Result<Vec<u8>, SignError> {
        if seed.len() != ffi::SECRET_KEY_BYTES {
            return Err(SignError::InvalidSeedLength {
                alg: "mldsa65",
                expected: ffi::SECRET_KEY_BYTES,
                actual: seed.len(),
            });
        }
        let mut sig = vec![0u8; ffi::SIGNATURE_BYTES];
        let mut siglen: usize = 0;
        let rc = unsafe {
            ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
                sig.as_mut_ptr(),
                &mut siglen as *mut usize,
                msg.as_ptr(),
                msg.len(),
                seed.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(SignError::PqcleanFailed("mldsa65 sign"));
        }
        if siglen != ffi::SIGNATURE_BYTES {
            return Err(SignError::InvalidSignatureLength {
                alg: "mldsa65",
                expected: ffi::SIGNATURE_BYTES,
                actual: siglen,
            });
        }
        Ok(sig)
    }
}

impl Verifier for MlDsa65 {
    fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, SignError> {
        verify::verify_raw(pubkey, msg, sig)
    }
}
