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
use super::super::types::{PageSize, VmFlags};
use super::core::VirtualMemoryManager;
use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::{frame_alloc, layout};

impl VirtualMemoryManager {
    pub(super) fn map_page_in_table(
        &self,
        va: VirtAddr,
        pa: PhysAddr,
        flags: VmFlags,
        page_size: PageSize,
    ) -> VmResult<()> {
        let pte_flags = self.vm_flags_to_pte(flags)
            | if page_size == PageSize::Size2M { PTE_HUGE_PAGE } else { 0 };
        unsafe {
            self.walk_page_table(va, true, |pte_ptr| {
                *pte_ptr = pa.as_u64() | pte_flags;
                Ok(())
            })
        }
    }

    pub(super) fn unmap_page_in_table(&self, va: VirtAddr, _page_size: PageSize) -> VmResult<()> {
        unsafe {
            self.walk_page_table(va, false, |pte_ptr| {
                *pte_ptr = 0;
                Ok(())
            })
        }
    }

    pub(super) unsafe fn walk_page_table<F>(
        &self,
        va: VirtAddr,
        create_tables: bool,
        mut callback: F,
    ) -> VmResult<()>
    where
        F: FnMut(*mut u64) -> VmResult<()>,
    {
        let l4_table = self.kernel_page_table.ok_or(VmError::NotInitialized)?.as_mut_ptr::<u64>();
        let l4_idx = l4_index(va.as_u64());
        let l3_idx = l3_index(va.as_u64());
        let l2_idx = l2_index(va.as_u64());
        let l1_idx = l1_index(va.as_u64());
        let l4_entry = l4_table.add(l4_idx);
        if !pte_is_present(*l4_entry) {
            if !create_tables {
                return Err(VmError::AddressNotMapped);
            }
            *l4_entry = frame_alloc::allocate_frame().ok_or(VmError::OutOfMemory)?.as_u64()
                | PTE_PRESENT
                | PTE_WRITABLE;
        }
        let l3_table = (pte_address(*l4_entry) + layout::KERNEL_BASE) as *mut u64;
        let l3_entry = l3_table.add(l3_idx);
        if !pte_is_present(*l3_entry) {
            if !create_tables {
                return Err(VmError::AddressNotMapped);
            }
            *l3_entry = frame_alloc::allocate_frame().ok_or(VmError::OutOfMemory)?.as_u64()
                | PTE_PRESENT
                | PTE_WRITABLE;
        }
        let l2_table = (pte_address(*l3_entry) + layout::KERNEL_BASE) as *mut u64;
        let l2_entry = l2_table.add(l2_idx);
        if !pte_is_present(*l2_entry) {
            if !create_tables {
                return Err(VmError::AddressNotMapped);
            }
            *l2_entry = frame_alloc::allocate_frame().ok_or(VmError::OutOfMemory)?.as_u64()
                | PTE_PRESENT
                | PTE_WRITABLE;
        }
        let l1_table = (pte_address(*l2_entry) + layout::KERNEL_BASE) as *mut u64;
        callback(l1_table.add(l1_idx))
    }

    pub(super) fn vm_flags_to_pte(&self, flags: VmFlags) -> u64 {
        let mut pte_flags = 0u64;
        if flags.contains(VmFlags::Present) {
            pte_flags |= PTE_PRESENT;
        }
        if flags.contains(VmFlags::Write) {
            pte_flags |= PTE_WRITABLE;
        }
        if flags.contains(VmFlags::User) {
            pte_flags |= PTE_USER;
        }
        if flags.contains(VmFlags::WriteThrough) {
            pte_flags |= PTE_WRITE_THROUGH;
        }
        if flags.contains(VmFlags::CacheDisable) {
            pte_flags |= PTE_CACHE_DISABLE;
        }
        if flags.contains(VmFlags::Global) {
            pte_flags |= PTE_GLOBAL;
        }
        if flags.contains(VmFlags::NoExecute) {
            pte_flags |= PTE_NO_EXECUTE;
        }
        pte_flags
    }
}
