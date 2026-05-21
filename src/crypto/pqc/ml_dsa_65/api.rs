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
use super::types::{
    MlDsa65Error, MlDsa65KeyPair, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature,
};
use super::{ffi, verify_stack};

#[inline]
fn ok(rc: i32) -> Result<(), MlDsa65Error> {
    if rc == 0 {
        Ok(())
    } else {
        Err(MlDsa65Error::FfiError)
    }
}

pub fn ml_dsa_65_keypair() -> Result<MlDsa65KeyPair, MlDsa65Error> {
    let mut pk = MlDsa65PublicKey { bytes: [0u8; PUBLICKEY_BYTES] };
    let mut sk = MlDsa65SecretKey { bytes: [0u8; SECRETKEY_BYTES] };
    let rc = unsafe { ffi::keypair(pk.bytes.as_mut_ptr(), sk.bytes.as_mut_ptr()) };
    ok(rc)?;
    Ok(MlDsa65KeyPair { public_key: pk, secret_key: sk })
}

pub fn ml_dsa_65_sign(sk: &MlDsa65SecretKey, msg: &[u8]) -> Result<MlDsa65Signature, MlDsa65Error> {
    let mut sig = MlDsa65Signature { bytes: [0u8; SIGNATURE_BYTES] };
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
        return Err(MlDsa65Error::FfiError);
    }
    Ok(sig)
}

pub fn ml_dsa_65_verify(pk: &MlDsa65PublicKey, msg: &[u8], sig: &MlDsa65Signature) -> bool {
    verify_stack::verify(
        sig.bytes.as_ptr(),
        SIGNATURE_BYTES,
        msg.as_ptr(),
        msg.len(),
        pk.bytes.as_ptr(),
    ) == 0
}

pub fn ml_dsa_65_verify_bytes(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, MlDsa65Error> {
    if pk.len() != PUBLICKEY_BYTES || sig.len() != SIGNATURE_BYTES {
        return Err(MlDsa65Error::InvalidLength);
    }
    let rc = verify_stack::verify(sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len(), pk.as_ptr());
    Ok(rc == 0)
}

pub fn ml_dsa_65_serialize_public_key(pk: &MlDsa65PublicKey) -> Vec<u8> {
    pk.bytes.to_vec()
}

pub fn ml_dsa_65_deserialize_public_key(data: &[u8]) -> Result<MlDsa65PublicKey, MlDsa65Error> {
    if data.len() != PUBLICKEY_BYTES {
        return Err(MlDsa65Error::InvalidLength);
    }
    let mut bytes = [0u8; PUBLICKEY_BYTES];
    bytes.copy_from_slice(data);
    Ok(MlDsa65PublicKey { bytes })
}

pub fn ml_dsa_65_serialize_secret_key(sk: &MlDsa65SecretKey) -> Vec<u8> {
    sk.bytes.to_vec()
}

pub fn ml_dsa_65_deserialize_secret_key(data: &[u8]) -> Result<MlDsa65SecretKey, MlDsa65Error> {
    if data.len() != SECRETKEY_BYTES {
        return Err(MlDsa65Error::InvalidLength);
    }
    let mut bytes = [0u8; SECRETKEY_BYTES];
    bytes.copy_from_slice(data);
    Ok(MlDsa65SecretKey { bytes })
}

pub fn ml_dsa_65_serialize_signature(sig: &MlDsa65Signature) -> Vec<u8> {
    sig.bytes.to_vec()
}

pub fn ml_dsa_65_deserialize_signature(data: &[u8]) -> Result<MlDsa65Signature, MlDsa65Error> {
    if data.len() != SIGNATURE_BYTES {
        return Err(MlDsa65Error::InvalidLength);
    }
    let mut bytes = [0u8; SIGNATURE_BYTES];
    bytes.copy_from_slice(data);
    Ok(MlDsa65Signature { bytes })
}
