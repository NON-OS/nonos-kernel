// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::constants::*;
use super::super::error::{VmError, VmResult};
use super::super::stats::VM_STATS;
use super::super::types::{MappedRange, PageSize, VmFlags};
use super::core::VirtualMemoryManager;
use crate::memory::addr::{PhysAddr, VirtAddr};

impl VirtualMemoryManager {
    pub fn map_page_4k(&mut self, va: VirtAddr, pa: PhysAddr, flags: VmFlags) -> VmResult<()> {
        if !self.initialized {
            return Err(VmError::NotInitialized);
        }
        self.validate_wx_permissions(flags)?;
        self.validate_alignment(va, pa, PageSize::Size4K)?;
        self.map_page_in_table(va, pa, flags, PageSize::Size4K)?;
        self.mapped_ranges.push(MappedRange::new(va, pa, PAGE_SIZE_4K, flags, PageSize::Size4K));
        VM_STATS.record_mapping(PAGE_SIZE_4K);
        self.flush_tlb_single(va);
        Ok(())
    }

    pub fn map_page_2m(&mut self, va: VirtAddr, pa: PhysAddr, flags: VmFlags) -> VmResult<()> {
        if !self.initialized {
            return Err(VmError::NotInitialized);
        }
        self.validate_wx_permissions(flags)?;
        self.validate_alignment(va, pa, PageSize::Size2M)?;
        self.map_page_in_table(va, pa, flags, PageSize::Size2M)?;
        self.mapped_ranges.push(MappedRange::new(va, pa, PAGE_SIZE_2M, flags, PageSize::Size2M));
        VM_STATS.record_mapping(PAGE_SIZE_2M);
        self.flush_tlb_single(va);
        Ok(())
    }

    pub fn unmap_page(&mut self, va: VirtAddr, page_size: PageSize) -> VmResult<()> {
        if !self.initialized {
            return Err(VmError::NotInitialized);
        }
        let range_idx = self
            .mapped_ranges
            .iter()
            .position(|r| r.start_va == va)
            .ok_or(VmError::AddressNotMapped)?;
        let range = self.mapped_ranges.remove(range_idx);
        self.unmap_page_in_table(va, page_size)?;
        VM_STATS.record_unmapping(range.size);
        self.flush_tlb_single(va);
        Ok(())
    }

    pub fn map_range(
        &mut self,
        va: VirtAddr,
        pa: PhysAddr,
        size: usize,
        flags: VmFlags,
    ) -> VmResult<()> {
        if size == 0 {
            return Err(VmError::InvalidRange);
        }
        let page_count = (size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;
        for i in 0..page_count {
            let page_va = VirtAddr::new(va.as_u64() + (i * PAGE_SIZE_4K) as u64);
            let page_pa = PhysAddr::new(pa.as_u64() + (i * PAGE_SIZE_4K) as u64);
            self.map_page_4k(page_va, page_pa, flags)?;
        }
        Ok(())
    }

    pub fn unmap_range(&mut self, va: VirtAddr, size: usize) -> VmResult<()> {
        if size == 0 {
            return Err(VmError::InvalidRange);
        }
        let page_count = (size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;
        for i in 0..page_count {
            self.unmap_page(
                VirtAddr::new(va.as_u64() + (i * PAGE_SIZE_4K) as u64),
                PageSize::Size4K,
            )?;
        }
        Ok(())
    }
}
