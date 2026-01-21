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

use core::mem;
use core::slice;

pub const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";
pub const RSDP_ALIGNMENT: usize = 16;
pub const EBDA_PTR_ADDR: usize = 0x040E;
pub const BIOS_ROM_START: usize = 0xE0000;
pub const BIOS_ROM_SIZE: usize = 0x20000;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Rsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32,
}

impl Rsdp {
    pub fn validate_checksum(&self) -> bool {
        // SAFETY: Reading packed struct as bytes for checksum validation
        let bytes = unsafe {
            slice::from_raw_parts(self as *const Self as *const u8, mem::size_of::<Self>())
        };
        bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
    }

    pub fn is_acpi2(&self) -> bool {
        self.revision >= 2
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RsdpExtended {
    pub base: Rsdp,
    pub length: u32,
    pub xsdt_address: u64,
    pub extended_checksum: u8,
    pub reserved: [u8; 3],
}

impl RsdpExtended {
    pub fn validate_extended_checksum(&self) -> bool {
        let len = self.length as usize;
        if len < mem::size_of::<Self>() {
            return false;
        }
        // SAFETY: Reading packed struct as bytes for checksum validation
        unsafe {
            let bytes = slice::from_raw_parts(self as *const Self as *const u8, len);
            bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
        }
    }

    pub fn from_rsdp(rsdp: Rsdp) -> Self {
        Self {
            base: rsdp,
            length: mem::size_of::<Rsdp>() as u32,
            xsdt_address: 0,
            extended_checksum: 0,
            reserved: [0; 3],
        }
    }

    pub fn has_xsdt(&self) -> bool {
        self.base.revision >= 2 && self.xsdt_address != 0
    }

    pub fn rsdt_address(&self) -> u32 {
        self.base.rsdt_address
    }
}
