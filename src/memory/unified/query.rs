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

use super::super::{paging, virt, virtual_memory};
use x86_64::{PhysAddr, VirtAddr};

#[inline]
pub fn translate_virtual(va: VirtAddr) -> Option<PhysAddr> {
    virt::translate_addr(va).ok()
}

#[inline]
pub fn is_address_mapped(va: VirtAddr) -> bool {
    virt::is_mapped(va) || paging::is_mapped(va)
}

pub fn handle_unified_page_fault(
    fault_addr: VirtAddr,
    error_code: u64,
) -> Result<(), &'static str> {
    if virtual_memory::handle_page_fault(fault_addr, error_code).is_ok() {
        return Ok(());
    }
    virt::handle_page_fault(fault_addr, error_code).map_err(|_| "Page fault handling failed")
}
