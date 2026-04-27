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

use super::free::free;
use super::guard::check_heap_guards;
use super::lock::{lock_heap, unlock_heap};
use super::state::*;
use super::types::*;
use crate::sys::serial;
use core::ptr::null_mut;
use core::sync::atomic::Ordering;

pub fn alloc(size: usize, align: usize) -> *mut u8 {
    if !HEAP_INIT.load(Ordering::Relaxed) || size == 0 {
        return null_mut();
    }

    if size > 1024 * 1024 {
        serial::print(b"[HEAP] Large alloc: ");
        serial::print_dec(size as u64 / 1024 / 1024);
        serial::println(b" MB");
    }

    lock_heap();

    check_heap_guards();

    let data_size = size.max(MIN_BLOCK_SIZE);
    let Some(total_size) = ALLOC_HEADER_SIZE.checked_add(data_size) else {
        unlock_heap();
        return null_mut();
    };
    let Some(aligned_size) =
        total_size.checked_add(align.saturating_sub(1)).map(|s| s & !(align - 1))
    else {
        unlock_heap();
        return null_mut();
    };

    let result = unsafe { alloc_from_freelist(aligned_size, align) };

    if !result.is_null() {
        let current = TOTAL_ALLOCATED.fetch_add(aligned_size, Ordering::Relaxed) + aligned_size;
        let peak = PEAK_USAGE.load(Ordering::Relaxed);
        if current > peak {
            PEAK_USAGE.store(current, Ordering::Relaxed);
        }
    }

    unlock_heap();
    result
}

unsafe fn alloc_from_freelist(size: usize, align: usize) -> *mut u8 {
    let mut prev: *mut BlockHeader = null_mut();
    let mut current = FREE_LIST;
    let mut iterations = 0u32;

    while !current.is_null() {
        iterations += 1;
        if iterations > 10000 {
            serial::println(b"[HEAP] ERROR: Infinite loop!");
            return null_mut();
        }

        if (*current).magic != BLOCK_MAGIC {
            serial::println(b"[HEAP] ERROR: Corrupted block!");
            return null_mut();
        }

        let block_size = (*current).size;
        let data_start = (current as usize) + ALLOC_HEADER_SIZE;
        let aligned_data = (data_start + align - 1) & !(align - 1);
        let padding = aligned_data - data_start;
        let needed_size = size + padding;

        if block_size >= needed_size {
            let remaining = block_size - needed_size;

            if remaining >= HEADER_SIZE + MIN_BLOCK_SIZE {
                let new_block = ((current as usize) + needed_size) as *mut BlockHeader;
                (*new_block).size = remaining;
                (*new_block).next = (*current).next;
                (*new_block).magic = BLOCK_MAGIC;

                if prev.is_null() {
                    FREE_LIST = new_block;
                } else {
                    (*prev).next = new_block;
                }

                let alloc_hdr = current as *mut AllocHeader;
                (*alloc_hdr).size = needed_size;
                (*alloc_hdr).magic = ALLOC_MAGIC;
                return aligned_data as *mut u8;
            } else {
                if prev.is_null() {
                    FREE_LIST = (*current).next;
                } else {
                    (*prev).next = (*current).next;
                }

                let alloc_hdr = current as *mut AllocHeader;
                (*alloc_hdr).size = block_size;
                (*alloc_hdr).magic = ALLOC_MAGIC;
                return aligned_data as *mut u8;
            }
        }

        prev = current;
        current = (*current).next;
    }

    null_mut()
}

pub fn realloc(ptr: *mut u8, new_size: usize, align: usize) -> *mut u8 {
    if ptr.is_null() {
        return alloc(new_size, align);
    }
    if new_size == 0 {
        free(ptr);
        return null_mut();
    }

    let old_size = unsafe {
        let hdr_addr = (ptr as usize).saturating_sub(ALLOC_HEADER_SIZE);
        let alloc_hdr = hdr_addr as *const AllocHeader;
        if (*alloc_hdr).magic != ALLOC_MAGIC {
            return null_mut();
        }
        (*alloc_hdr).size - ALLOC_HEADER_SIZE
    };

    if new_size <= old_size {
        return ptr;
    }

    let new_ptr = alloc(new_size, align);
    if new_ptr.is_null() {
        return null_mut();
    }

    unsafe {
        core::ptr::copy_nonoverlapping(ptr, new_ptr, old_size.min(new_size));
    }
    free(ptr);
    new_ptr
}
