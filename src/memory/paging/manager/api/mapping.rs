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

use super::globals::{PAGING_MANAGER, PAGING_STATS};
use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::paging::constants::{pages_needed, PAGE_SIZE_4K};
use crate::memory::paging::error::PagingResult;
use crate::memory::paging::types::{PagePermissions, PageSize};

pub fn map_page(
    virtual_addr: VirtAddr,
    physical_addr: PhysAddr,
    permissions: PagePermissions,
) -> PagingResult<()> {
    PAGING_MANAGER.lock().map_page(
        virtual_addr,
        physical_addr,
        permissions,
        PageSize::Size4KiB,
        &PAGING_STATS,
    )
}

pub fn map_huge_page(
    virtual_addr: VirtAddr,
    physical_addr: PhysAddr,
    permissions: PagePermissions,
    size: PageSize,
) -> PagingResult<()> {
    PAGING_MANAGER.lock().map_page(virtual_addr, physical_addr, permissions, size, &PAGING_STATS)
}

pub fn unmap_page(virtual_addr: VirtAddr) -> PagingResult<PhysAddr> {
    let (phys, perms, size) = PAGING_MANAGER.lock().unmap_page(virtual_addr)?;
    PAGING_STATS.record_unmapping(perms, size);
    Ok(phys)
}

// Multi-page unmap. Walks 4 KiB pages from `virtual_addr` for `size`
// bytes (rounded up). Stops at the first failure and returns it.
pub fn unmap_range(virtual_addr: VirtAddr, size: usize) -> PagingResult<()> {
    for i in 0..pages_needed(size) {
        let va = VirtAddr::new(virtual_addr.as_u64() + (i * PAGE_SIZE_4K) as u64);
        unmap_page(va)?;
    }
    Ok(())
}

pub fn map_kernel_page(virtual_addr: VirtAddr, physical_addr: PhysAddr) -> PagingResult<()> {
    let permissions = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::GLOBAL;
    map_page(virtual_addr, physical_addr, permissions)
}

pub fn map_user_page(
    virtual_addr: VirtAddr,
    physical_addr: PhysAddr,
    writable: bool,
) -> PagingResult<()> {
    let mut permissions = PagePermissions::READ | PagePermissions::USER;
    if writable {
        permissions = permissions | PagePermissions::WRITE;
    }
    map_page(virtual_addr, physical_addr, permissions)
}

pub fn map_device_memory(
    virtual_addr: VirtAddr,
    physical_addr: PhysAddr,
    size: usize,
) -> PagingResult<()> {
    let permissions = PagePermissions::READ
        | PagePermissions::WRITE
        | PagePermissions::NO_CACHE
        | PagePermissions::DEVICE;
    for i in 0..pages_needed(size) {
        let va = VirtAddr::new(virtual_addr.as_u64() + (i * PAGE_SIZE_4K) as u64);
        let pa = PhysAddr::new(physical_addr.as_u64() + (i * PAGE_SIZE_4K) as u64);
        map_page(va, pa, permissions)?;
    }
    Ok(())
}
