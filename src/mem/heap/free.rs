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

use super::guard::{check_heap_guards, validate_heap_ptr};
use super::lock::{lock_heap, unlock_heap};
use super::state::*;
use super::types::*;
use crate::sys::serial;
use core::sync::atomic::Ordering;

/// # Safety
/// Frees heap allocation. Validates pointer is in heap bounds and checks
/// guard pages for corruption before completing the free operation.
pub fn free(ptr: *mut u8) {
    if ptr.is_null() || !HEAP_INIT.load(Ordering::Relaxed) {
        return;
    }

    lock_heap();

    let heap_start = unsafe { HEAP_START };
    let heap_end = unsafe { HEAP_END };

    if !validate_heap_ptr(ptr as usize, heap_start, heap_end) {
        serial::println(b"[HEAP] ERROR: free ptr outside heap bounds!");
        unlock_heap();
        return;
    }

    check_heap_guards();

    unsafe {
        let hdr_addr = (ptr as usize).saturating_sub(ALLOC_HEADER_SIZE);
        let alloc_hdr = hdr_addr as *mut AllocHeader;

        if (*alloc_hdr).magic != ALLOC_MAGIC {
            serial::println(b"[HEAP] ERROR: Invalid free - bad magic!");
            unlock_heap();
            return;
        }

        let block_size = (*alloc_hdr).size;
        TOTAL_FREED.fetch_add(block_size, Ordering::Relaxed);
        TOTAL_ALLOCATED.fetch_sub(block_size, Ordering::Relaxed);

        let free_block = hdr_addr as *mut BlockHeader;
        (*free_block).size = block_size;
        (*free_block).magic = BLOCK_MAGIC;

        insert_free_block(free_block);
        coalesce_free_blocks();
    }

    unlock_heap();
}

/// # Safety
/// Inserts block into sorted free list for coalescing.
unsafe fn insert_free_block(block: *mut BlockHeader) {
    let block_addr = block as usize;

    if FREE_LIST.is_null() || block_addr < FREE_LIST as usize {
        (*block).next = FREE_LIST;
        FREE_LIST = block;
        return;
    }

    let mut current = FREE_LIST;
    while !(*current).next.is_null() && ((*current).next as usize) < block_addr {
        current = (*current).next;
    }

    (*block).next = (*current).next;
    (*current).next = block;
}

/// # Safety
/// Merges adjacent free blocks to reduce fragmentation.
unsafe fn coalesce_free_blocks() {
    let mut current = FREE_LIST;

    while !current.is_null() && !(*current).next.is_null() {
        let next = (*current).next;
        let current_end = (current as usize) + (*current).size;

        if current_end == next as usize {
            (*current).size += (*next).size;
            (*current).next = (*next).next;
        } else {
            current = next;
        }
    }
}
