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

use crate::crypto::asymmetric::ed25519;

pub fn ed25519_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, &'static str> {
    if pk.len() != 32 || sig.len() != 64 {
        return Ok(false);
    }
    let mut pk_array = [0u8; 32];
    let mut sig_array = [0u8; 64];
    pk_array.copy_from_slice(pk);
    sig_array.copy_from_slice(sig);
    let sig_obj = ed25519::Signature::from_bytes(&sig_array);
    Ok(ed25519::verify(&pk_array, msg, &sig_obj))
}

pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    if signature.len() == 64 && public_key.len() == 32 {
        let mut sig_array = [0u8; 64];
        let mut key_array = [0u8; 32];
        sig_array.copy_from_slice(signature);
        key_array.copy_from_slice(public_key);

        let sig_struct = ed25519::Signature::from_bytes(&sig_array);
        ed25519::verify(&key_array, message, &sig_struct)
    } else {
        false
    }
}
