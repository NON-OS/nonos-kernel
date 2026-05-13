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

use super::endian::be_u32;
use super::error::FdtError;
use super::tokens::{FDT_LAST_COMP_VERSION, FDT_MAGIC};

#[derive(Debug, Clone, Copy)]
pub struct FdtHeader {
    pub totalsize: u32,
    pub off_dt_struct: u32,
    pub off_dt_strings: u32,
    pub off_mem_rsvmap: u32,
    pub version: u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys: u32,
    pub size_dt_strings: u32,
    pub size_dt_struct: u32,
}

// Header layout is 40 bytes of BE u32 fields starting with magic.
pub const HEADER_SIZE: usize = 40;

pub fn parse(blob: &[u8]) -> Result<FdtHeader, FdtError> {
    if blob.len() < HEADER_SIZE {
        return Err(FdtError::OutOfBounds);
    }
    let magic = be_u32(blob, 0)?;
    if magic != FDT_MAGIC {
        return Err(FdtError::BadMagic);
    }
    let last_comp_version = be_u32(blob, 24)?;
    if last_comp_version > FDT_LAST_COMP_VERSION {
        return Err(FdtError::BadVersion);
    }
    let header = FdtHeader {
        totalsize: be_u32(blob, 4)?,
        off_dt_struct: be_u32(blob, 8)?,
        off_dt_strings: be_u32(blob, 12)?,
        off_mem_rsvmap: be_u32(blob, 16)?,
        version: be_u32(blob, 20)?,
        last_comp_version,
        boot_cpuid_phys: be_u32(blob, 28)?,
        size_dt_strings: be_u32(blob, 32)?,
        size_dt_struct: be_u32(blob, 36)?,
    };
    if (header.totalsize as usize) < HEADER_SIZE {
        return Err(FdtError::TotalSizeTooSmall);
    }
    Ok(header)
}
