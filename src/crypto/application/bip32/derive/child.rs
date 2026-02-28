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

use super::super::extended_key::{ExtendedPrivateKey, HARDENED_OFFSET};
use crate::crypto::asymmetric::secp256k1::public_key_from_secret;
use crate::crypto::util::hmac::hmac_sha512;
use crate::crypto::{CryptoError, CryptoResult};
use super::validate::{is_valid_secret_key, is_valid_tweak};
use super::scalar_math::{add_scalars, compress_pubkey};

pub fn derive_child(
    parent: &ExtendedPrivateKey,
    index: u32,
) -> CryptoResult<ExtendedPrivateKey> {
    let hardened = index >= HARDENED_OFFSET;

    let mut data = Vec::with_capacity(37);

    if hardened {
        data.push(0x00);
        data.extend_from_slice(parent.secret_key());
    } else {
        let pk = public_key_from_secret(parent.secret_key())
            .ok_or(CryptoError::InvalidKey)?;
        let compressed = compress_pubkey(&pk)?;
        data.extend_from_slice(&compressed);
    }

    data.extend_from_slice(&index.to_be_bytes());

    let hmac_result = hmac_sha512(parent.chain_code(), &data);

    let mut il = [0u8; 32];
    let mut chain_code = [0u8; 32];
    il.copy_from_slice(&hmac_result[..32]);
    chain_code.copy_from_slice(&hmac_result[32..]);

    if !is_valid_tweak(&il) {
        return Err(CryptoError::InvalidKey);
    }

    let child_key = add_scalars(parent.secret_key(), &il)?;

    if !is_valid_secret_key(&child_key) {
        return Err(CryptoError::InvalidKey);
    }

    let parent_fp = parent.fingerprint()?;

    Ok(ExtendedPrivateKey::with_metadata(
        child_key,
        chain_code,
        parent.depth().saturating_add(1),
        parent_fp,
        index,
    ))
}
