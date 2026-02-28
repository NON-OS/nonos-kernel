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

extern crate alloc;
use alloc::vec::Vec;

use super::constants::{PUBLICKEY_BYTES, SECRETKEY_BYTES, SIGNATURE_BYTES};
use super::types::{DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature, DilithiumKeyPair, DilithiumError};
use super::ffi;

#[inline]
fn ok(rc: i32) -> Result<(), DilithiumError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(DilithiumError::FfiError)
    }
}

pub fn dilithium_keypair() -> Result<DilithiumKeyPair, DilithiumError> {
    let mut pk = DilithiumPublicKey { bytes: [0u8; PUBLICKEY_BYTES] };
    let mut sk = DilithiumSecretKey { bytes: [0u8; SECRETKEY_BYTES] };
    let rc = unsafe { ffi::keypair(pk.bytes.as_mut_ptr(), sk.bytes.as_mut_ptr()) };
    ok(rc)?;
    Ok(DilithiumKeyPair { public_key: pk, secret_key: sk })
}

pub fn dilithium_sign(sk: &DilithiumSecretKey, msg: &[u8]) -> Result<DilithiumSignature, DilithiumError> {
    let mut sig = DilithiumSignature { bytes: [0u8; SIGNATURE_BYTES] };
    let mut siglen: usize = 0;
    let rc = unsafe {
        ffi::sign(
            sig.bytes.as_mut_ptr(),
            &mut siglen as *mut usize,
            msg.as_ptr(),
            msg.len(),
            sk.bytes.as_ptr(),
        )
    };
    ok(rc)?;
    if siglen != SIGNATURE_BYTES {
        return Err(DilithiumError::FfiError);
    }
    Ok(sig)
}

pub fn dilithium_verify(pk: &DilithiumPublicKey, msg: &[u8], sig: &DilithiumSignature) -> bool {
    let rc = unsafe {
        ffi::verify(
            sig.bytes.as_ptr(),
            SIGNATURE_BYTES,
            msg.as_ptr(),
            msg.len(),
            pk.bytes.as_ptr(),
        )
    };
    rc == 0
}

pub fn dilithium_serialize_public_key(pk: &DilithiumPublicKey) -> Vec<u8> {
    pk.bytes.to_vec()
}

pub fn dilithium_deserialize_public_key(data: &[u8]) -> Result<DilithiumPublicKey, DilithiumError> {
    if data.len() != PUBLICKEY_BYTES {
        return Err(DilithiumError::InvalidLength);
    }
    let mut bytes = [0u8; PUBLICKEY_BYTES];
    bytes.copy_from_slice(data);
    Ok(DilithiumPublicKey { bytes })
}

pub fn dilithium_serialize_secret_key(sk: &DilithiumSecretKey) -> Vec<u8> {
    sk.bytes.to_vec()
}

pub fn dilithium_deserialize_secret_key(data: &[u8]) -> Result<DilithiumSecretKey, DilithiumError> {
    if data.len() != SECRETKEY_BYTES {
        return Err(DilithiumError::InvalidLength);
    }
    let mut bytes = [0u8; SECRETKEY_BYTES];
    bytes.copy_from_slice(data);
    Ok(DilithiumSecretKey { bytes })
}

pub fn dilithium_serialize_signature(sig: &DilithiumSignature) -> Vec<u8> {
    sig.bytes.to_vec()
}

pub fn dilithium_deserialize_signature(data: &[u8]) -> Result<DilithiumSignature, DilithiumError> {
    if data.len() != SIGNATURE_BYTES {
        return Err(DilithiumError::InvalidLength);
    }
    let mut bytes = [0u8; SIGNATURE_BYTES];
    bytes.copy_from_slice(data);
    Ok(DilithiumSignature { bytes })
}
