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

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

use crate::error::SignError;

pub fn raw(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, SignError> {
    if pubkey.len() != 32 {
        return Err(SignError::InvalidPubkeyLength {
            alg: "ed25519",
            expected: 32,
            actual: pubkey.len(),
        });
    }
    if sig.len() != 64 {
        return Err(SignError::InvalidSignatureLength {
            alg: "ed25519",
            expected: 64,
            actual: sig.len(),
        });
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(pubkey);
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return Err(SignError::PubkeyDecode),
    };
    let mut sb = [0u8; 64];
    sb.copy_from_slice(sig);
    let s = Signature::from_bytes(&sb);
    Ok(vk.verify(msg, &s).is_ok())
}
