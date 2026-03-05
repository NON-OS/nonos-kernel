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

use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

use super::core::PagingManager;
use crate::memory::paging::constants::{PAGE_SIZE_4K, pages_needed};
use crate::memory::paging::error::PagingResult;
use crate::memory::paging::stats::PagingStatistics;
use crate::memory::paging::tlb;
use crate::memory::paging::types::{PageMapping, PagePermissions, PageSize, PagingStats};
use crate::memory::layout;

static PAGING_MANAGER: Mutex<PagingManager> = Mutex::new(PagingManager::new());
static PAGING_STATS: PagingStatistics = PagingStatistics::new();

pub fn init() -> PagingResult<()> {
    PAGING_MANAGER.lock().init()
}

pub fn is_initialized() -> bool {
    PAGING_MANAGER.lock().is_initialized()
}

pub fn map_page(virtual_addr: VirtAddr, physical_addr: PhysAddr, permissions: PagePermissions) -> PagingResult<()> {
    PAGING_MANAGER.lock().map_page(virtual_addr, physical_addr, permissions, PageSize::Size4KiB, &PAGING_STATS)
}

pub fn map_huge_page(virtual_addr: VirtAddr, physical_addr: PhysAddr, permissions: PagePermissions, size: PageSize) -> PagingResult<()> {
    PAGING_MANAGER.lock().map_page(virtual_addr, physical_addr, permissions, size, &PAGING_STATS)
}

pub fn unmap_page(virtual_addr: VirtAddr) -> PagingResult<PhysAddr> {
    let (phys, perms, size) = PAGING_MANAGER.lock().unmap_page(virtual_addr)?;
    PAGING_STATS.record_unmapping(perms, size);
    Ok(phys)
}

pub fn map_kernel_page(virtual_addr: VirtAddr, physical_addr: PhysAddr) -> PagingResult<()> {
    let permissions = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::GLOBAL;
    map_page(virtual_addr, physical_addr, permissions)
}

pub fn map_user_page(virtual_addr: VirtAddr, physical_addr: PhysAddr, writable: bool) -> PagingResult<()> {
    let mut permissions = PagePermissions::READ | PagePermissions::USER;
    if writable {
        permissions = permissions | PagePermissions::WRITE;
    }
    map_page(virtual_addr, physical_addr, permissions)
}

pub fn map_device_memory(virtual_addr: VirtAddr, physical_addr: PhysAddr, size: usize) -> PagingResult<()> {
    let permissions = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::NO_CACHE | PagePermissions::DEVICE;
    let page_count = pages_needed(size);
    for i in 0..page_count {
        let va = VirtAddr::new(virtual_addr.as_u64() + (i * PAGE_SIZE_4K) as u64);
        let pa = PhysAddr::new(physical_addr.as_u64() + (i * PAGE_SIZE_4K) as u64);
        map_page(va, pa, permissions)?;
    }
    Ok(())
}

pub fn translate_address(virtual_addr: VirtAddr) -> Option<PhysAddr> {
    PAGING_MANAGER.lock().translate_address(virtual_addr).ok()
}

pub fn is_mapped(virtual_addr: VirtAddr) -> bool {
    translate_address(virtual_addr).is_some()
}

pub fn update_page_flags(virtual_addr: VirtAddr, new_permissions: PagePermissions) -> PagingResult<()> {
    PAGING_MANAGER.lock().update_page_flags(virtual_addr, new_permissions, &PAGING_STATS)
}

pub fn update_page_protection(virtual_addr: VirtAddr, permissions: PagePermissions) -> PagingResult<()> {
    update_page_flags(virtual_addr, permissions)
}

pub fn protect_pages(start_va: VirtAddr, page_count: usize, permissions: PagePermissions) -> PagingResult<()> {
    for i in 0..page_count {
        let va = VirtAddr::new(start_va.as_u64() + (i * PAGE_SIZE_4K) as u64);
        update_page_flags(va, permissions)?;
    }
    Ok(())
}

pub fn protect_pages_range(start_addr: VirtAddr, page_count: usize, permissions: PagePermissions) -> PagingResult<()> {
    protect_pages(start_addr, page_count, permissions)
}

pub fn create_address_space(process_id: u32) -> PagingResult<u32> {
    PAGING_MANAGER.lock().create_address_space(process_id)
}

pub fn switch_address_space(asid: u32) -> PagingResult<()> {
    PAGING_MANAGER.lock().switch_address_space(asid)
}

pub fn cleanup_address_space(asid: u32) -> PagingResult<()> {
    PAGING_MANAGER.lock().cleanup_address_space(asid)
}

pub fn handle_page_fault(virtual_addr: VirtAddr, error_code: u64) -> PagingResult<()> {
    PAGING_MANAGER.lock().handle_page_fault(virtual_addr, error_code, &PAGING_STATS)
}

pub fn flush_tlb(virtual_addr: Option<VirtAddr>) -> PagingResult<()> {
    PAGING_STATS.record_tlb_flush();
    match virtual_addr {
        Some(addr) => tlb::invalidate_page(addr),
        None => tlb::invalidate_all(),
    }
    Ok(())
}

pub fn invalidate_page(va: VirtAddr) {
    tlb::invalidate_page(va);
    PAGING_STATS.record_tlb_flush();
}

pub fn invalidate_all_pages() {
    tlb::invalidate_all();
    PAGING_STATS.record_tlb_flush();
}

pub fn get_current_cr3() -> PhysAddr {
    tlb::get_cr3()
}

pub fn set_cr3(page_table_pa: PhysAddr) {
    tlb::set_cr3(page_table_pa);
}

pub fn enable_write_protection() {
    tlb::enable_write_protection();
}

/// # Safety
/// Caller must re-enable write protection immediately after use.
pub unsafe fn disable_write_protection() {
    unsafe { tlb::disable_write_protection(); }
}

pub fn get_mapping_info(virtual_addr: VirtAddr) -> Option<PageMapping> {
    PAGING_MANAGER.lock().get_mapping_info(virtual_addr).cloned()
}

pub fn get_page_permissions(virtual_addr: VirtAddr) -> Option<PagePermissions> {
    get_mapping_info(virtual_addr).map(|m| m.permissions)
}

pub fn get_paging_stats() -> PagingStats {
    let manager = PAGING_MANAGER.lock();
    PAGING_STATS.snapshot(manager.mappings_count(), manager.address_spaces_count())
}

pub fn get_memory_usage() -> (usize, usize) {
    let stats = get_paging_stats();
    (stats.user_pages * layout::PAGE_SIZE, stats.kernel_pages * layout::PAGE_SIZE)
}
