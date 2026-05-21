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

use crate::crypto::{blake3, Nonce};

use super::types::{PacketError, REPLAY_TAG_LEN};

pub fn compute(
    session_id: u32,
    flags: u8,
    nonce: &Nonce,
    ciphertext: &[u8],
) -> Result<[u8; REPLAY_TAG_LEN], PacketError> {
    let mut material = Vec::with_capacity(17 + ciphertext.len());
    material.extend_from_slice(&session_id.to_le_bytes());
    material.push(flags);
    material.extend_from_slice(nonce);
    material.extend_from_slice(ciphertext);
    let mut out = [0u8; REPLAY_TAG_LEN];
    blake3(&material, &mut out).map_err(|_| PacketError::Crypto)?;
    Ok(out)
}
