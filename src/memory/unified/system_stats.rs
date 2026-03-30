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

use super::super::{heap, layout, phys, safety, buddy_alloc as allocator};

pub struct MemorySystemStats {
    pub heap_stats: heap::HeapStats,
    pub alloc_stats: allocator::AllocStats,
    pub safety_stats: safety::MemoryStats,
    pub total_physical_memory: u64,
    pub total_virtual_memory: u64,
    pub active_allocations: usize,
}

pub fn get_memory_system_stats() -> MemorySystemStats {
    MemorySystemStats {
        heap_stats: heap::get_heap_stats(),
        alloc_stats: allocator::get_allocation_stats(),
        safety_stats: safety::get_stats(),
        total_physical_memory: phys::total_memory(),
        total_virtual_memory: layout::VMAP_SIZE,
        active_allocations: allocator::get_allocation_stats().active_ranges,
    }
}
