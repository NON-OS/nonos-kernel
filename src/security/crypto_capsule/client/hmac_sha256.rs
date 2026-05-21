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

use alloc::vec::Vec;

use super::super::error::CryptoCapsuleError;
use super::prf_op;

const OP_HMAC_SHA256: u16 = 16;

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], CryptoCapsuleError> {
    let mut body = Vec::with_capacity(4 + key.len() + data.len());
    body.extend_from_slice(&(key.len() as u32).to_le_bytes());
    body.extend_from_slice(key);
    body.extend_from_slice(data);
    prf_op::fixed32(OP_HMAC_SHA256, &body)
}
