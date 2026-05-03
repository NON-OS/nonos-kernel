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
use super::super::types::{PageSize, VmFlags, VmStatsSnapshot};
use super::core::VirtualMemoryManager;
use crate::memory::addr::{PhysAddr, VirtAddr};
use spin::Mutex;

static VIRTUAL_MEMORY_MANAGER: Mutex<VirtualMemoryManager> =
    Mutex::new(VirtualMemoryManager::new());

pub fn init(cr3_frame: PhysAddr) -> VmResult<()> {
    VIRTUAL_MEMORY_MANAGER.lock().init(cr3_frame)
}
pub fn map_page_4k(
    va: VirtAddr,
    pa: PhysAddr,
    writable: bool,
    user: bool,
    executable: bool,
) -> VmResult<()> {
    let mut mgr = VIRTUAL_MEMORY_MANAGER.lock();
    if !mgr.is_initialized() {
        let cr3 = crate::memory::paging::tlb::get_cr3();
        mgr.init(cr3)?;
    }
    mgr.map_page_4k(va, pa, build_flags(writable, user, executable))
}
pub fn map_page_2m(
    va: VirtAddr,
    pa: PhysAddr,
    writable: bool,
    user: bool,
    executable: bool,
) -> VmResult<()> {
    VIRTUAL_MEMORY_MANAGER.lock().map_page_2m(va, pa, build_flags(writable, user, executable))
}
pub fn unmap_page(va: VirtAddr) -> VmResult<()> {
    VIRTUAL_MEMORY_MANAGER.lock().unmap_page(va, PageSize::Size4K)
}
pub fn unmap_page_2m(va: VirtAddr) -> VmResult<()> {
    VIRTUAL_MEMORY_MANAGER.lock().unmap_page(va, PageSize::Size2M)
}
pub fn map_range(
    va: VirtAddr,
    pa: PhysAddr,
    size: usize,
    writable: bool,
    user: bool,
    executable: bool,
) -> VmResult<()> {
    VIRTUAL_MEMORY_MANAGER.lock().map_range(va, pa, size, build_flags(writable, user, executable))
}
pub fn unmap_range(va: VirtAddr, size: usize) -> VmResult<()> {
    VIRTUAL_MEMORY_MANAGER.lock().unmap_range(va, size)
}
pub fn translate_addr(va: VirtAddr) -> VmResult<PhysAddr> {
    let (pa, _, _) = VIRTUAL_MEMORY_MANAGER.lock().translate(va)?;
    Ok(pa)
}
pub fn translate_with_flags(va: VirtAddr) -> VmResult<(PhysAddr, VmFlags, usize)> {
    VIRTUAL_MEMORY_MANAGER.lock().translate(va)
}
pub fn flush_tlb() {
    VIRTUAL_MEMORY_MANAGER.lock().flush_tlb_all();
}
pub fn flush_tlb_page(va: VirtAddr) {
    VIRTUAL_MEMORY_MANAGER.lock().flush_tlb_single(va);
}
pub fn is_mapped(va: VirtAddr) -> bool {
    VIRTUAL_MEMORY_MANAGER.lock().find_mapped_range(va).is_some()
}

pub fn validate_range(va: VirtAddr, size: usize, required_flags: VmFlags) -> bool {
    let manager = VIRTUAL_MEMORY_MANAGER.lock();
    let page_count = (size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;
    for i in 0..page_count {
        let page_va = VirtAddr::new(va.as_u64() + (i * PAGE_SIZE_4K) as u64);
        if let Some(range) = manager.find_mapped_range(page_va) {
            if !range.flags.contains(required_flags) {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

pub fn handle_page_fault(_va: VirtAddr, error_code: u64) -> VmResult<()> {
    VM_STATS.record_page_fault();
    if (error_code & PF_PRESENT) == 0 {
        return Err(VmError::AddressNotMapped);
    }
    if (error_code & PF_WRITE) != 0 {
        return Err(VmError::PermissionViolation);
    }
    Ok(())
}

pub fn get_stats() -> VmStatsSnapshot {
    VM_STATS.snapshot()
}

pub fn is_kpti_enabled() -> bool {
    let cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    (cr4 & CR4_PCIDE) != 0
}

fn build_flags(writable: bool, user: bool, executable: bool) -> VmFlags {
    let mut flags = VmFlags::Present;
    if writable {
        flags = flags | VmFlags::Write;
    }
    if user {
        flags = flags | VmFlags::User;
    }
    if !executable {
        flags = flags | VmFlags::NoExecute;
    }
    flags
}
