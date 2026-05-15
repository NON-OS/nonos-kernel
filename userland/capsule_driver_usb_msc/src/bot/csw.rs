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

use crate::protocol::{CSW_LEN, E_INVAL, E_PHASE};

const CSW_SIGNATURE: u32 = 0x5342_5355;

#[derive(Clone, Copy)]
pub struct CommandStatus {
    pub tag: u32,
    pub residue: u32,
    pub status: u8,
}

pub fn parse(raw: &[u8]) -> Result<CommandStatus, i32> {
    if raw.len() != CSW_LEN {
        return Err(E_INVAL);
    }
    let sig = u32::from_le_bytes(raw[0..4].try_into().map_err(|_| E_INVAL)?);
    if sig != CSW_SIGNATURE {
        return Err(E_INVAL);
    }
    let tag = u32::from_le_bytes(raw[4..8].try_into().map_err(|_| E_INVAL)?);
    let residue = u32::from_le_bytes(raw[8..12].try_into().map_err(|_| E_INVAL)?);
    let status = raw[12];
    if status > 2 {
        return Err(E_PHASE);
    }
    Ok(CommandStatus { tag, residue, status })
}
