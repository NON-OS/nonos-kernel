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

use core::fmt;

/// # Safety
/// Boot parameters from bootloader. All fields must be validated before use.
/// Untrusted data from firmware/bootloader.
#[derive(Debug, Clone, Copy)]
pub struct BootParams {
    pub mmap_ptr: u64,
    pub mmap_entry_size: u32,
    pub mmap_entry_count: u32,
    pub fb_addr: u64,
    pub fb_width: u32,
    pub fb_height: u32,
    pub fb_stride: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootParamsError {
    NullMemoryMap,
    InvalidEntrySize,
    InvalidEntryCount,
    MemoryMapTooLarge,
    InvalidFramebuffer,
    FramebufferTooLarge,
}

impl fmt::Display for BootParamsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullMemoryMap => write!(f, "null memory map pointer"),
            Self::InvalidEntrySize => write!(f, "invalid memory map entry size"),
            Self::InvalidEntryCount => write!(f, "invalid memory map entry count"),
            Self::MemoryMapTooLarge => write!(f, "memory map exceeds safe bounds"),
            Self::InvalidFramebuffer => write!(f, "invalid framebuffer address"),
            Self::FramebufferTooLarge => write!(f, "framebuffer exceeds safe bounds"),
        }
    }
}

const MAX_MMAP_ENTRIES: u32 = 1024;
const MIN_ENTRY_SIZE: u32 = 24;
const MAX_ENTRY_SIZE: u32 = 256;
const MAX_FB_DIMENSION: u32 = 8192;

/// # Safety
/// Validates boot parameters from bootloader. Returns error if any field
/// is outside safe bounds. Must be called before using boot params.
pub fn validate_boot_params(params: &BootParams) -> Result<(), BootParamsError> {
    if params.mmap_ptr == 0 {
        return Err(BootParamsError::NullMemoryMap);
    }

    if params.mmap_entry_size < MIN_ENTRY_SIZE || params.mmap_entry_size > MAX_ENTRY_SIZE {
        return Err(BootParamsError::InvalidEntrySize);
    }

    if params.mmap_entry_count == 0 || params.mmap_entry_count > MAX_MMAP_ENTRIES {
        return Err(BootParamsError::InvalidEntryCount);
    }

    let mmap_size = (params.mmap_entry_size as u64)
        .checked_mul(params.mmap_entry_count as u64)
        .ok_or(BootParamsError::MemoryMapTooLarge)?;

    if mmap_size > 1024 * 1024 {
        return Err(BootParamsError::MemoryMapTooLarge);
    }

    if params.fb_addr != 0 {
        if params.fb_width == 0 || params.fb_width > MAX_FB_DIMENSION {
            return Err(BootParamsError::InvalidFramebuffer);
        }
        if params.fb_height == 0 || params.fb_height > MAX_FB_DIMENSION {
            return Err(BootParamsError::InvalidFramebuffer);
        }

        let fb_size = (params.fb_stride as u64)
            .checked_mul(params.fb_height as u64)
            .ok_or(BootParamsError::FramebufferTooLarge)?;

        if fb_size > 256 * 1024 * 1024 {
            return Err(BootParamsError::FramebufferTooLarge);
        }
    }

    Ok(())
}
