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

use crate::protocol::CBW_LEN;

const CBW_SIGNATURE: u32 = 0x4342_5355;
pub const CBW_FLAG_IN: u8 = 0x80;
pub const CBW_FLAG_OUT: u8 = 0x00;

pub struct CommandBlockWrapper {
    pub tag: u32,
    pub data_len: u32,
    pub flags: u8,
    pub lun: u8,
    pub cdb_len: u8,
    pub cdb: [u8; 16],
}

impl CommandBlockWrapper {
    pub fn write(&self, out: &mut [u8]) {
        out[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        out[4..8].copy_from_slice(&self.tag.to_le_bytes());
        out[8..12].copy_from_slice(&self.data_len.to_le_bytes());
        out[12] = self.flags;
        out[13] = self.lun;
        out[14] = self.cdb_len;
        out[15..CBW_LEN].copy_from_slice(&self.cdb);
    }
}
