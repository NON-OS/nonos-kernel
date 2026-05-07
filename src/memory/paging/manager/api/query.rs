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

use super::globals::PAGING_MANAGER;
use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::paging::types::{PageMapping, PagePermissions};

pub fn translate_address(virtual_addr: VirtAddr) -> Option<PhysAddr> {
    PAGING_MANAGER.lock().translate_address(virtual_addr).ok()
}

pub fn is_mapped(virtual_addr: VirtAddr) -> bool {
    translate_address(virtual_addr).is_some()
}

pub fn get_mapping_info(virtual_addr: VirtAddr) -> Option<PageMapping> {
    PAGING_MANAGER.lock().get_mapping_info(virtual_addr).cloned()
}

pub fn get_page_permissions(virtual_addr: VirtAddr) -> Option<PagePermissions> {
    get_mapping_info(virtual_addr).map(|m| m.permissions)
}

// Active CR3 as recorded by the paging manager. `None` until
// `manager::api::init()` has run.
pub fn active_page_table() -> Option<PhysAddr> {
    PAGING_MANAGER.lock().active_page_table()
}

// Number of registered address spaces. Used by boot-time validation
// to confirm `create_kernel_address_space` ran inside `init()`.
pub fn address_spaces_count() -> usize {
    PAGING_MANAGER.lock().address_spaces_count()
}

pub fn active_asid() -> Option<u32> {
    PAGING_MANAGER.lock().active_asid()
}
