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

use crate::memory::addr::VirtAddr;
use crate::memory::nonos_layout as layout;
use crate::memory::paging::types::PagePermissions;
use crate::smp::constants::PERCPU_STACK_SIZE;

pub(super) fn allocate(cpu_id: usize) -> Result<u64, &'static str> {
    let stack_base = layout::PERCPU_STACKS_BASE + (cpu_id as u64 * PERCPU_STACK_SIZE as u64);
    let pages = PERCPU_STACK_SIZE / layout::PAGE_SIZE;

    for i in 0..pages {
        let va = VirtAddr::new(stack_base + (i * layout::PAGE_SIZE) as u64);
        map_stack_page(va)?;
    }

    Ok(stack_base)
}

fn map_stack_page(va: VirtAddr) -> Result<(), &'static str> {
    let Some(pa) = crate::memory::nonos_frame_alloc::allocate_frame() else {
        return Err("Failed to allocate CPU stack frame");
    };

    let perms = PagePermissions::READ | PagePermissions::WRITE;
    crate::memory::paging::manager::map_page(va, pa, perms)
        .map_err(|_| "Failed to map CPU stack page")
}
