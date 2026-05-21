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

use crate::crypto::{blake3, Key};
use crate::packet::PacketError;

pub fn route_seed(
    session_id: u32,
    flags: u8,
    key: &Key,
    cred: &[u8; 32],
) -> Result<[u8; 32], PacketError> {
    let mut material = Vec::with_capacity(69);
    material.extend_from_slice(key);
    material.extend_from_slice(cred);
    material.extend_from_slice(&session_id.to_le_bytes());
    material.push(flags);
    let mut out = [0u8; 32];
    blake3(&material, &mut out).map_err(|_| PacketError::Crypto)?;
    Ok(out)
}
