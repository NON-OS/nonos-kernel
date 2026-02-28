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

use crate::arch::x86_64::uefi::crc;
use crate::arch::x86_64::uefi::error::UefiError;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

impl TableHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn verify_signature(&self, expected: u64) -> Result<(), UefiError> {
        if self.signature != expected {
            return Err(UefiError::InvalidSignature {
                expected,
                found: self.signature,
            });
        }
        Ok(())
    }

    // SAFETY: Caller must ensure the raw pointer points to valid memory of at least header_size bytes
    pub unsafe fn verify_crc(&self, base: *const u8) -> Result<(), UefiError> {
        if self.header_size < Self::SIZE as u32 {
            return Err(UefiError::InvalidParameter {
                param: "header_size",
            });
        }

        let header_bytes = core::slice::from_raw_parts(base, self.header_size as usize);
        let computed = crc::compute_table_crc(header_bytes, 16);

        if computed != self.crc32 {
            return Err(UefiError::CrcMismatch {
                expected: self.crc32,
                computed,
            });
        }
        Ok(())
    }

    pub fn major_version(&self) -> u16 {
        (self.revision >> 16) as u16
    }

    pub fn minor_version(&self) -> u16 {
        self.revision as u16
    }
}
