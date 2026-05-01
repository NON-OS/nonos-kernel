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
use crate::memory::virt;
use crate::memory::addr::{PhysAddr, VirtAddr};

pub(super) fn map_page(virt_addr: VirtAddr, phys_addr: PhysAddr) -> BuddyAllocResult<()> {
    virt::map_page_4k(virt_addr, phys_addr, true, true, false)
        .map_err(|_| BuddyAllocError::MappingFailed)
}

pub(super) fn unmap_page(virt_addr: VirtAddr) -> BuddyAllocResult<Option<PhysAddr>> {
    let pa = virt::translate_addr(virt_addr).map_err(|_| BuddyAllocError::TranslationFailed)?;
    virt::unmap_page(virt_addr).map_err(|_| BuddyAllocError::UnmapFailed)?;
    Ok(Some(pa))
}
