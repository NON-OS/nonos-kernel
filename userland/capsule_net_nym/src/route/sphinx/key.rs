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

use crate::crypto::hkdf_sha256;
use crate::packet::PacketError;

pub fn hop_key(
    seed: &[u8; 32],
    idx: u8,
    cred: &[u8; 32],
    shared: &[u8; 32],
) -> Result<[u8; 32], PacketError> {
    let mut info = Vec::with_capacity(60);
    info.extend_from_slice(b"NONOS-NYM-SPHINX-HOP-v1");
    info.extend_from_slice(seed);
    info.push(idx);
    let mut out = [0u8; 32];
    hkdf_sha256(cred, shared, &info, &mut out).map_err(|_| PacketError::Crypto)?;
    Ok(out)
}
