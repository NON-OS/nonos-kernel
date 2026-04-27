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

use super::super::constants::{KERNEL_PHYS_END, KERNEL_PHYS_START, MAX_DMA_SIZE};
use super::super::error::NvmeError;
use x86_64::PhysAddr;

pub struct DmaValidator;

impl DmaValidator {
    pub fn validate_buffer(phys_addr: PhysAddr, size: usize) -> Result<(), NvmeError> {
        let start = phys_addr.as_u64();
        if size == 0 {
            return Err(NvmeError::DmaBufferSizeZero);
        }
        if size > MAX_DMA_SIZE {
            return Err(NvmeError::DmaBufferTooLarge);
        }
        let end = start.checked_add(size as u64).ok_or(NvmeError::DmaBufferAddressOverflow)?;
        if Self::overlaps_kernel(start, end) {
            return Err(NvmeError::DmaBufferOverlapsKernel);
        }
        Ok(())
    }

    pub fn validate_prp(prp: u64, page_size: usize) -> Result<(), NvmeError> {
        if (prp as usize) & 0x3 != 0 {
            return Err(NvmeError::InvalidPrpAlignment);
        }
        let page_offset = prp as usize & (page_size - 1);
        if page_offset != 0 && page_offset < 4 {
            return Err(NvmeError::InvalidPrpAlignment);
        }
        Ok(())
    }

    #[inline]
    fn overlaps_kernel(start: u64, end: u64) -> bool {
        if start >= KERNEL_PHYS_START && start < KERNEL_PHYS_END {
            return true;
        }
        if end > KERNEL_PHYS_START && end <= KERNEL_PHYS_END {
            return true;
        }
        if start < KERNEL_PHYS_START && end > KERNEL_PHYS_END {
            return true;
        }
        false
    }
}
