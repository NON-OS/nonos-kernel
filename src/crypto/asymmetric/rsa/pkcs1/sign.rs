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

use super::super::keys::{rsa_private_operation, RsaPrivateKey};
use super::digest::pkcs1_digest_info_sha256;
use super::padding::pkcs1_pad_type1;
use crate::crypto::hash::sha256;
use crate::crypto::util::bigint::BigUint;
use crate::crypto::CryptoResult;
use alloc::vec::Vec;

pub fn sign_pkcs1v15(private_key: &RsaPrivateKey, message: &[u8]) -> CryptoResult<Vec<u8>> {
    let hash = sha256(message);
    let digest_info = pkcs1_digest_info_sha256(&hash);
    let padded = pkcs1_pad_type1(&digest_info, private_key.bits / 8)?;
    let signature = rsa_private_operation(&BigUint::from_bytes_be(&padded), private_key)?;
    Ok(signature.to_bytes_be())
}

pub fn sign_message(msg: &[u8], key: &RsaPrivateKey) -> Result<Vec<u8>, &'static str> {
    sign_pkcs1v15(key, msg).map_err(|_| "RSA signing failed")
}
