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

use super::super::core::PagingManager;
use crate::memory::paging::constants::*;
use crate::memory::paging::error::{PagingError, PagingResult};
use crate::memory::paging::tlb;
use crate::memory::{frame_alloc, layout};
use crate::memory::addr::{PhysAddr, VirtAddr};

fn alloc_table(entry: &mut u64) -> PagingResult<()> {
    let new = frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;
    *entry = new.as_u64() | PTE_TABLE_FLAGS;
    unsafe {
        core::ptr::write_bytes((layout::DIRECTMAP_BASE + new.as_u64()) as *mut u8, 0, PAGE_SIZE_4K);
    }
    Ok(())
}

fn table_at(pa: PhysAddr) -> *mut [u64; PAGE_TABLE_ENTRIES] {
    (layout::DIRECTMAP_BASE + pa.as_u64()) as *mut [u64; PAGE_TABLE_ENTRIES]
}

impl PagingManager {
    pub(in crate::memory::paging::manager) fn install_mapping(
        &self,
        va: VirtAddr,
        pa: PhysAddr,
        flags: u64,
    ) -> PagingResult<()> {
        let va_val = va.as_u64();
        let (l4_idx, l3_idx, l2_idx, l1_idx) =
            (pml4_index(va_val), pdpt_index(va_val), pd_index(va_val), pt_index(va_val));
        let cr3 = self.active_page_table.ok_or(PagingError::NoActivePageTable)?;
        unsafe {
            let l4 = &mut *table_at(cr3);
            if !pte_is_present(l4[l4_idx]) {
                alloc_table(&mut l4[l4_idx])?;
            }
            let l3 = &mut *table_at(PhysAddr::new(pte_address(l4[l4_idx])));
            if !pte_is_present(l3[l3_idx]) {
                alloc_table(&mut l3[l3_idx])?;
            }
            let l2 = &mut *table_at(PhysAddr::new(pte_address(l3[l3_idx])));
            if !pte_is_present(l2[l2_idx]) {
                alloc_table(&mut l2[l2_idx])?;
            }
            let l1 = &mut *table_at(PhysAddr::new(pte_address(l2[l2_idx])));
            l1[l1_idx] = pa.as_u64() | flags;
        }
        tlb::invalidate_page(va);
        Ok(())
    }
}
