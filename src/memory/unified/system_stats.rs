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

use super::super::{buddy_alloc as allocator, heap, layout, phys};

#[derive(Clone, Copy, Default)]
pub struct MemorySystemStats {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub buffers_bytes: u64,
    pub cached_bytes: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    pub slab_bytes: u64,
    pub sreclaimable: u64,
    pub sunreclaim: u64,
    pub kernel_stack: u64,
    pub page_tables: u64,
    pub vmalloc_total: u64,
    pub vmalloc_used: u64,
    pub heap_used: u64,
    pub heap_free: u64,
    pub active_allocations: usize,
}

pub fn get_memory_system_stats() -> MemorySystemStats {
    let heap_stats = heap::get_heap_stats();
    let alloc_stats = allocator::get_allocation_stats();
    let total = phys::total_memory();
    let free = phys::free_memory();
    MemorySystemStats {
        total_bytes: total,
        free_bytes: free,
        available_bytes: free,
        buffers_bytes: 0,
        cached_bytes: heap_stats.total_allocated.saturating_sub(heap_stats.total_deallocated) / 4,
        swap_total: 0,
        swap_free: 0,
        slab_bytes: alloc_stats.total_allocated,
        sreclaimable: alloc_stats.total_allocated / 2,
        sunreclaim: alloc_stats.total_allocated / 2,
        kernel_stack: 8192 * 64,
        page_tables: alloc_stats.active_ranges as u64 * 4096,
        vmalloc_total: layout::VMAP_SIZE,
        vmalloc_used: heap_stats.total_allocated.saturating_sub(heap_stats.total_deallocated),
        heap_used: heap_stats.total_allocated.saturating_sub(heap_stats.total_deallocated),
        heap_free: heap_stats.total_deallocated,
        active_allocations: alloc_stats.active_ranges,
    }
}
