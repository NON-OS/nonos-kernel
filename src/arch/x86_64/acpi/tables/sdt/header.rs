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

use core::mem;
use core::slice;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SdtHeader {
    pub signature: u32,
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

impl SdtHeader {
    pub fn signature_bytes(&self) -> [u8; 4] {
        self.signature.to_le_bytes()
    }

    pub fn validate_checksum(&self, table_ptr: *const u8) -> bool {
        if self.length < mem::size_of::<Self>() as u32 {
            return false;
        }
        // SAFETY: Caller ensures table_ptr is valid for self.length bytes
        unsafe {
            let bytes = slice::from_raw_parts(table_ptr, self.length as usize);
            bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
        }
    }

    pub fn data_length(&self) -> u32 {
        self.length.saturating_sub(mem::size_of::<Self>() as u32)
    }
}
