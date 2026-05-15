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

use crate::protocol::{E_INVAL, E_OVERFLOW, MAX_TRANSFER_BLOCKS};

pub fn block_request(body: &[u8]) -> Result<(u32, u16), i32> {
    if body.len() != 6 {
        return Err(E_INVAL);
    }
    let lba = u32::from_le_bytes(body[0..4].try_into().map_err(|_| E_INVAL)?);
    let blocks = u16::from_le_bytes(body[4..6].try_into().map_err(|_| E_INVAL)?);
    if blocks == 0 {
        return Err(E_INVAL);
    }
    if blocks > MAX_TRANSFER_BLOCKS {
        return Err(E_OVERFLOW);
    }
    Ok((lba, blocks))
}
