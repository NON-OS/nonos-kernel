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

use core::slice;

use super::error::FdtError;
use super::header::{self, FdtHeader};
use super::walker::Walker;

// Root view over a flat device-tree blob. Holds borrowed slices into
// the structure and strings blocks; the caller owns the backing bytes.
pub struct Fdt<'a> {
    pub header: FdtHeader,
    pub blob: &'a [u8],
    pub structure: &'a [u8],
    pub strings: &'a [u8],
}

impl<'a> Fdt<'a> {
    pub fn from_ptr(ptr: *const u8) -> Result<Self, FdtError> {
        if ptr.is_null() {
            return Err(FdtError::NullPointer);
        }
        // SAFETY: the bootloader/firmware delivers a contiguous FDT
        // blob; we read 40 bytes to parse the header, then narrow to
        // totalsize. Out-of-range header reads are still caught by
        // header::parse's length check.
        let header_bytes = unsafe { slice::from_raw_parts(ptr, header::HEADER_SIZE) };
        let header = header::parse(header_bytes)?;
        let total = header.totalsize as usize;
        // SAFETY: caller-supplied DTB blob; size taken from header
        // after magic + version validation.
        let blob = unsafe { slice::from_raw_parts(ptr, total) };
        let struct_start = header.off_dt_struct as usize;
        let struct_end = struct_start
            .checked_add(header.size_dt_struct as usize)
            .ok_or(FdtError::OutOfBounds)?;
        let strings_start = header.off_dt_strings as usize;
        let strings_end = strings_start
            .checked_add(header.size_dt_strings as usize)
            .ok_or(FdtError::OutOfBounds)?;
        if struct_end > total || strings_end > total {
            return Err(FdtError::OutOfBounds);
        }
        Ok(Self {
            header,
            blob,
            structure: &blob[struct_start..struct_end],
            strings: &blob[strings_start..strings_end],
        })
    }

    pub fn walker(&self) -> Walker<'a> {
        Walker::new(self.structure, self.strings)
    }
}
