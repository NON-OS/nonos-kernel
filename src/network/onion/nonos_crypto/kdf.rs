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


use alloc::{format, vec::Vec};
use crate::crypto::{hash, hmac};
use crate::network::onion::OnionError;

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, OnionError> {
    let result = hmac::hmac_sha256(key, data);
    Ok(result.to_vec())
}

pub fn hkdf_extract_expand(secret: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, OnionError> {
    hmac::hkdf(salt, secret, info, len).map_err(|_| OnionError::CryptoError)
}

pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8], out: &mut [u8; 32]) -> Result<(), OnionError> {
    let result = hash::hmac_sha256(salt, ikm);
    out.copy_from_slice(&result);
    Ok(())
}

pub fn hkdf_expand_sha256(prk: &[u8; 32], info: &[u8], _length: usize, out: &mut [u8]) -> Result<(), OnionError> {
    hash::hkdf_expand(prk, info, out).map_err(|_| OnionError::CryptoError)
}

pub fn derive_layer_keys(shared_secret: &[u8], layer_info: &[u8]) -> Result<([u8; 32], [u8; 32]), OnionError> {
    let forward_info = format!(
        "tor-forward-{}",
        core::str::from_utf8(layer_info).unwrap_or("unknown")
    );
    let forward_key = hkdf_extract_expand(shared_secret, b"tor-kdf", forward_info.as_bytes(), 32)?;

    let backward_info = format!(
        "tor-backward-{}",
        core::str::from_utf8(layer_info).unwrap_or("unknown")
    );
    let backward_key = hkdf_extract_expand(shared_secret, b"tor-kdf", backward_info.as_bytes(), 32)?;

    let mut fwd_key = [0u8; 32];
    let mut bwd_key = [0u8; 32];
    fwd_key.copy_from_slice(&forward_key[..32]);
    bwd_key.copy_from_slice(&backward_key[..32]);

    Ok((fwd_key, bwd_key))
}

#[cfg(feature = "sha1-legacy")]
#[allow(deprecated)]
pub fn tap_derive_keys(dh_output: &[u8]) -> Result<([u8; 16], [u8; 16], [u8; 20]), OnionError> {
    let k = hash::sha1(dh_output);

    let mut forward_key = [0u8; 16];
    let mut backward_key = [0u8; 16];
    let mut key_material = [0u8; 20];

    forward_key.copy_from_slice(&k[..16]);
    backward_key.copy_from_slice(&k[4..20]);
    key_material.copy_from_slice(&k);

    Ok((forward_key, backward_key, key_material))
}

pub fn ntor_derive_keys(xy: &[u8], xb: &[u8]) -> Result<([u8; 32], [u8; 32], [u8; 32]), OnionError> {
    let mut key_seed = Vec::with_capacity(xy.len() + xb.len());
    key_seed.extend_from_slice(xy);
    key_seed.extend_from_slice(xb);

    let forward_key = hkdf_extract_expand(&key_seed, b"ntor-forward", b"", 32)?;
    let backward_key = hkdf_extract_expand(&key_seed, b"ntor-backward", b"", 32)?;
    let verify_key = hkdf_extract_expand(&key_seed, b"ntor-verify", b"", 32)?;

    let mut fwd = [0u8; 32];
    let mut bwd = [0u8; 32];
    let mut verify = [0u8; 32];

    fwd.copy_from_slice(&forward_key[..32]);
    bwd.copy_from_slice(&backward_key[..32]);
    verify.copy_from_slice(&verify_key[..32]);

    Ok((fwd, bwd, verify))
}
