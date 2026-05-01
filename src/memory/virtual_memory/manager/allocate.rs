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
use super::super::types::{VmProtection, VmType};
use super::api::map_memory_range;
use crate::memory::addr::VirtAddr;

pub fn allocate_user_stack(size: usize) -> Result<VirtAddr, &'static str> {
    let stack_bottom = VirtAddr::new(USER_STACK_BOTTOM - size as u64);
    let area_id = map_memory_range(stack_bottom, size, VmProtection::ReadWrite, VmType::Stack)?;
    crate::log::debug!("vmem: allocated user stack area {}", area_id);
    Ok(stack_bottom)
}

pub fn allocate_user_heap(initial_size: usize) -> Result<VirtAddr, &'static str> {
    let heap_start = VirtAddr::new(USER_HEAP_START);
    let area_id =
        map_memory_range(heap_start, initial_size, VmProtection::ReadWrite, VmType::Heap)?;
    crate::log::debug!("vmem: allocated user heap area {}", area_id);
    Ok(heap_start)
}

pub fn allocate_shared_memory(size: usize) -> Result<VirtAddr, &'static str> {
    let shared_start = VirtAddr::new(SHARED_MEMORY_START);
    let area_id = map_memory_range(shared_start, size, VmProtection::ReadWrite, VmType::Shared)?;
    crate::log::debug!("vmem: allocated shared memory area {}", area_id);
    Ok(shared_start)
}
