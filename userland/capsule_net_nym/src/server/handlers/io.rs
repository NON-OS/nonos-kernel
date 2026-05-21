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

use crate::protocol::E_BAD_LEN;

pub fn u16_at(body: &[u8], off: usize) -> Result<u16, u16> {
    body.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or(E_BAD_LEN)
}

pub fn u32_at(body: &[u8], off: usize) -> Result<u32, u16> {
    body.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or(E_BAD_LEN)
}

pub fn ip4_at(body: &[u8], off: usize) -> Result<[u8; 4], u16> {
    let bytes = body.get(off..off + 4).ok_or(E_BAD_LEN)?;
    Ok([bytes[0], bytes[1], bytes[2], bytes[3]])
}
