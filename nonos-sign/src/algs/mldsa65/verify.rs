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

use crate::error::SignError;

use super::ffi;

pub fn verify_raw(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, SignError> {
    if pubkey.len() != ffi::PUBLIC_KEY_BYTES {
        return Err(SignError::InvalidPubkeyLength {
            alg: "mldsa65",
            expected: ffi::PUBLIC_KEY_BYTES,
            actual: pubkey.len(),
        });
    }
    if sig.len() != ffi::SIGNATURE_BYTES {
        return Err(SignError::InvalidSignatureLength {
            alg: "mldsa65",
            expected: ffi::SIGNATURE_BYTES,
            actual: sig.len(),
        });
    }
    let rc = unsafe {
        ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
            sig.as_ptr(),
            sig.len(),
            msg.as_ptr(),
            msg.len(),
            pubkey.as_ptr(),
        )
    };
    Ok(rc == 0)
}
