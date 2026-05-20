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

use alloc::{vec, vec::Vec};

use crate::crypto::fill_random;

use super::types::{PacketError, AEAD_PLAIN_BYTES};

pub fn padded_plaintext(plaintext: &[u8]) -> Result<Vec<u8>, PacketError> {
    let mut plain = vec![0u8; AEAD_PLAIN_BYTES];
    fill_random(&mut plain).map_err(|_| PacketError::Crypto)?;
    plain[0..2].copy_from_slice(&(plaintext.len() as u16).to_le_bytes());
    plain[2..2 + plaintext.len()].copy_from_slice(plaintext);
    Ok(plain)
}
