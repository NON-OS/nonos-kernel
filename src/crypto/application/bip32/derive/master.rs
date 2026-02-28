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

use super::super::extended_key::ExtendedPrivateKey;
use crate::crypto::util::hmac::hmac_sha512;
use crate::crypto::{CryptoError, CryptoResult};
use super::validate::is_valid_secret_key;

pub fn derive_master_key(seed: &[u8]) -> CryptoResult<ExtendedPrivateKey> {
    if seed.len() < 16 || seed.len() > 64 {
        return Err(CryptoError::InvalidLength);
    }

    let hmac_key = b"Bitcoin seed";
    let hmac_result = hmac_sha512(hmac_key, seed);

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];

    key.copy_from_slice(&hmac_result[..32]);
    chain_code.copy_from_slice(&hmac_result[32..]);

    if !is_valid_secret_key(&key) {
        return Err(CryptoError::InvalidKey);
    }

    Ok(ExtendedPrivateKey::new(key, chain_code))
}
