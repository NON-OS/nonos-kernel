// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::{MULTIBOOT2_ARCHITECTURE_I386, MULTIBOOT2_HEADER_MAGIC};

#[repr(C, align(8))]
pub struct Multiboot2Header {
    pub magic: u32,
    pub architecture: u32,
    pub header_length: u32,
    pub checksum: u32,
}

impl Multiboot2Header {
    pub const fn new(header_length: u32) -> Self {
        let checksum = (0u32)
            .wrapping_sub(MULTIBOOT2_HEADER_MAGIC)
            .wrapping_sub(MULTIBOOT2_ARCHITECTURE_I386)
            .wrapping_sub(header_length);
        Self {
            magic: MULTIBOOT2_HEADER_MAGIC,
            architecture: MULTIBOOT2_ARCHITECTURE_I386,
            header_length,
            checksum,
        }
    }

    pub const fn verify_checksum(&self) -> bool {
        self.magic
            .wrapping_add(self.architecture)
            .wrapping_add(self.header_length)
            .wrapping_add(self.checksum)
            == 0
    }
}

#[repr(C)]
pub struct Multiboot2Info {
    pub total_size: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct TagHeader {
    pub tag_type: u32,
    pub size: u32,
}
