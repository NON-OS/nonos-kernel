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

use super::super::super::error::{BuddyAllocError, BuddyAllocResult};
use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::paging::manager;
use crate::memory::paging::types::PagePermissions;

pub(super) fn map_page(virt_addr: VirtAddr, phys_addr: PhysAddr) -> BuddyAllocResult<()> {
    let perms = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::USER;
    manager::map_page(virt_addr, phys_addr, perms).map_err(|_| BuddyAllocError::MappingFailed)
}

pub(super) fn unmap_page(virt_addr: VirtAddr) -> BuddyAllocResult<Option<PhysAddr>> {
    let pa = manager::translate_address(virt_addr).ok_or(BuddyAllocError::TranslationFailed)?;
    manager::unmap_page(virt_addr).map_err(|_| BuddyAllocError::UnmapFailed)?;
    Ok(Some(pa))
}
