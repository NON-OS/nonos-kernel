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

use crate::security::crypto_capsule::client as crypto_client;
use crate::security::crypto_capsule::CryptoCapsuleError;
use alloc::vec::Vec;

pub(super) fn digest(algo: u64, input: &[u8]) -> Result<Vec<u8>, CryptoCapsuleError> {
    match algo {
        0 => crypto_client::hash_blake3(input).map(|d| Vec::from(d.as_slice())),
        1 => crypto_client::hash_sha256(input).map(|d| Vec::from(d.as_slice())),
        2 => crypto_client::hash_sha512(input).map(|d| Vec::from(d.as_slice())),
        3 => crypto_client::hash_sha3_256(input).map(|d| Vec::from(d.as_slice())),
        _ => Err(CryptoCapsuleError::InvalidArgument),
    }
}
