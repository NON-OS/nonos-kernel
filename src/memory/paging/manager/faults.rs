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

use x86_64::VirtAddr;

use super::core::PagingManager;
use crate::memory::paging::constants::*;
use crate::memory::paging::error::{PagingError, PagingResult};
use crate::memory::paging::stats::PagingStatistics;
use crate::memory::paging::types::{PagePermissions, PageSize};
use crate::memory::{frame_alloc, layout};

impl PagingManager {
    pub fn handle_page_fault(
        &mut self,
        virtual_addr: VirtAddr,
        error_code: u64,
        stats: &PagingStatistics,
    ) -> PagingResult<()> {
        stats.record_page_fault();

        if error_code & PF_WRITE != 0 && error_code & PF_PRESENT != 0 {
            stats.record_cow_fault();
            return self.handle_cow_fault(virtual_addr, stats);
        }

        if error_code & PF_PRESENT == 0 {
            stats.record_demand_load();
            return self.handle_demand_fault(virtual_addr, stats);
        }

        Err(PagingError::UnhandledPageFault)
    }

    fn handle_cow_fault(
        &mut self,
        virtual_addr: VirtAddr,
        stats: &PagingStatistics,
    ) -> PagingResult<()> {
        let new_frame =
            frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;

        if let Ok(original_pa) = self.translate_address(virtual_addr) {
            // SAFETY: Copying memory between valid frames
            unsafe {
                let src_va = layout::DIRECTMAP_BASE + original_pa.as_u64();
                let dst_va = layout::DIRECTMAP_BASE + new_frame.as_u64();
                core::ptr::copy_nonoverlapping(
                    src_va as *const u8,
                    dst_va as *mut u8,
                    PAGE_SIZE_4K,
                );
            }
        }

        let permissions = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::USER;
        self.map_page(
            virtual_addr,
            new_frame,
            permissions,
            PageSize::Size4KiB,
            stats,
        )?;

        Ok(())
    }

    fn handle_demand_fault(
        &mut self,
        virtual_addr: VirtAddr,
        stats: &PagingStatistics,
    ) -> PagingResult<()> {
        let new_frame =
            frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;

        // SAFETY: Zeroing newly allocated frame
        unsafe {
            let va = layout::DIRECTMAP_BASE + new_frame.as_u64();
            core::ptr::write_bytes(va as *mut u8, 0, PAGE_SIZE_4K);
        }

        let permissions = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::USER;
        self.map_page(
            virtual_addr,
            new_frame,
            permissions,
            PageSize::Size4KiB,
            stats,
        )?;

        Ok(())
    }
}
