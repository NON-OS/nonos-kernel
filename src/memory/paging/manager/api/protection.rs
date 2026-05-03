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
use crate::memory::addr::VirtAddr;
use crate::memory::paging::constants::PAGE_SIZE_4K;
use crate::memory::paging::error::PagingResult;
use crate::memory::paging::types::PagePermissions;

pub fn update_page_flags(
    virtual_addr: VirtAddr,
    new_permissions: PagePermissions,
) -> PagingResult<()> {
    PAGING_MANAGER.lock().update_page_flags(virtual_addr, new_permissions, &PAGING_STATS)
}

pub fn update_page_protection(
    virtual_addr: VirtAddr,
    permissions: PagePermissions,
) -> PagingResult<()> {
    update_page_flags(virtual_addr, permissions)
}

pub fn protect_pages(
    start_va: VirtAddr,
    page_count: usize,
    permissions: PagePermissions,
) -> PagingResult<()> {
    for i in 0..page_count {
        let va = VirtAddr::new(start_va.as_u64() + (i * PAGE_SIZE_4K) as u64);
        update_page_flags(va, permissions)?;
    }
    Ok(())
}

pub fn protect_pages_range(
    start_addr: VirtAddr,
    page_count: usize,
    permissions: PagePermissions,
) -> PagingResult<()> {
    protect_pages(start_addr, page_count, permissions)
}
