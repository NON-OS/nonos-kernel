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

use core::ptr;
use x86_64::PhysAddr;

use super::super::constants::PAGE_SIZE;
use super::super::error::NvmeError;
use super::region::DmaRegion;

pub struct PrpList {
    region: DmaRegion,
    entry_count: usize,
}

impl PrpList {
    const ENTRIES_PER_PAGE: usize = PAGE_SIZE / 8;

    pub fn allocate(entry_count: usize) -> Result<Self, NvmeError> {
        let pages_needed = (entry_count + Self::ENTRIES_PER_PAGE - 1) / Self::ENTRIES_PER_PAGE;
        let size = pages_needed * PAGE_SIZE;

        let region = DmaRegion::allocate(size).map_err(|_| NvmeError::PrpListAllocationFailed)?;

        Ok(Self {
            region,
            entry_count,
        })
    }

    pub fn set_entry(&mut self, index: usize, phys_addr: u64) {
        if index < self.entry_count {
            // SAFETY: index is bounds-checked, pointer is valid and aligned
            unsafe {
                let ptr = self.region.as_mut_ptr::<u64>().add(index);
                ptr::write_volatile(ptr, phys_addr);
            }
        }
    }

    pub fn get_entry(&self, index: usize) -> Option<u64> {
        if index < self.entry_count {
            // SAFETY: index is bounds-checked, pointer is valid and aligned
            unsafe {
                let ptr = self.region.as_ptr::<u64>().add(index);
                Some(ptr::read_volatile(ptr))
            }
        } else {
            None
        }
    }

    #[inline]
    pub const fn phys_addr(&self) -> PhysAddr {
        self.region.phys_addr()
    }

    #[inline]
    pub const fn phys_u64(&self) -> u64 {
        self.region.phys_u64()
    }

    #[inline]
    pub const fn capacity(&self) -> usize {
        self.entry_count
    }
}

pub fn validate_prp_alignment(phys_addr: u64) -> Result<(), NvmeError> {
    if (phys_addr as usize) & 0x3 != 0 {
        return Err(NvmeError::InvalidPrpAlignment);
    }
    Ok(())
}

pub struct PrpBuilder {
    prp1: u64,
    prp2: u64,
    prp_list: Option<PrpList>,
}

impl PrpBuilder {
    pub fn build(buf_phys: PhysAddr, size: usize) -> Result<Self, NvmeError> {
        let base = buf_phys.as_u64();
        let first_page_offset = (base as usize) & (PAGE_SIZE - 1);
        let first_page_remaining = PAGE_SIZE - first_page_offset;

        if size <= first_page_remaining {
            return Ok(Self {
                prp1: base,
                prp2: 0,
                prp_list: None,
            });
        }

        let remaining_after_first = size - first_page_remaining;
        if remaining_after_first <= PAGE_SIZE {
            let prp2 = (base & !((PAGE_SIZE as u64) - 1)) + PAGE_SIZE as u64;
            return Ok(Self {
                prp1: base,
                prp2,
                prp_list: None,
            });
        }

        let pages_needed = (remaining_after_first + PAGE_SIZE - 1) / PAGE_SIZE;
        let mut prp_list = PrpList::allocate(pages_needed)?;

        let mut next_page = (base & !((PAGE_SIZE as u64) - 1)) + PAGE_SIZE as u64;
        for i in 0..pages_needed {
            prp_list.set_entry(i, next_page);
            next_page += PAGE_SIZE as u64;
        }

        Ok(Self {
            prp1: base,
            prp2: prp_list.phys_u64(),
            prp_list: Some(prp_list),
        })
    }

    #[inline]
    pub const fn prp1(&self) -> u64 {
        self.prp1
    }

    #[inline]
    pub const fn prp2(&self) -> u64 {
        self.prp2
    }

    pub fn into_prps(self) -> (u64, u64, Option<PrpList>) {
        (self.prp1, self.prp2, self.prp_list)
    }
}
