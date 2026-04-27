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

use crate::mem::{MemoryDescriptor, MemoryType};
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryMapError {
    InvalidPointer,
    InvalidEntrySize,
    OverlappingRegions,
    AddressOverflow,
    InvalidPageCount,
}

impl fmt::Display for MemoryMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPointer => write!(f, "invalid memory map pointer"),
            Self::InvalidEntrySize => write!(f, "invalid entry size"),
            Self::OverlappingRegions => write!(f, "overlapping memory regions"),
            Self::AddressOverflow => write!(f, "address overflow in region"),
            Self::InvalidPageCount => write!(f, "invalid page count"),
        }
    }
}

const MAX_PHYS_ADDR: u64 = 0x0001_0000_0000_0000;
const MAX_PAGES_PER_REGION: u64 = 0x1_0000_0000;

/// # Safety
/// Validates memory map entries from firmware. Checks for overlaps,
/// overflows, and invalid values. Must be called before using memory map.
pub fn validate_memory_map(
    mmap_ptr: u64,
    entry_size: u32,
    entry_count: u32,
) -> Result<(), MemoryMapError> {
    if mmap_ptr == 0 {
        return Err(MemoryMapError::InvalidPointer);
    }

    if entry_size < 24 {
        return Err(MemoryMapError::InvalidEntrySize);
    }

    for i in 0..entry_count {
        let entry_addr = mmap_ptr
            .checked_add((i as u64) * (entry_size as u64))
            .ok_or(MemoryMapError::AddressOverflow)?;

        let entry = unsafe { &*(entry_addr as *const MemoryDescriptor) };

        if entry.num_pages > MAX_PAGES_PER_REGION {
            return Err(MemoryMapError::InvalidPageCount);
        }

        let region_end = entry
            .phys_start
            .checked_add(entry.num_pages.saturating_mul(4096))
            .ok_or(MemoryMapError::AddressOverflow)?;

        if region_end > MAX_PHYS_ADDR {
            continue;
        }

        for j in (i + 1)..entry_count {
            let other_addr = mmap_ptr + (j as u64) * (entry_size as u64);
            let other = unsafe { &*(other_addr as *const MemoryDescriptor) };

            let other_end = other.phys_start.saturating_add(other.num_pages.saturating_mul(4096));

            let entry_type = MemoryType::from_u32_or_reserved(entry.mem_type);
            let other_type = MemoryType::from_u32_or_reserved(other.mem_type);

            if entry_type.is_usable() && other_type.is_usable() {
                if regions_overlap(entry.phys_start, region_end, other.phys_start, other_end) {
                    return Err(MemoryMapError::OverlappingRegions);
                }
            }
        }
    }

    Ok(())
}

fn regions_overlap(start1: u64, end1: u64, start2: u64, end2: u64) -> bool {
    start1 < end2 && start2 < end1
}
