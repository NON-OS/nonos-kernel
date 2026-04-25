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

use super::guard::{write_guard, HEAP_GUARD_HIGH, HEAP_GUARD_LOW};
use super::state::{FREE_LIST, HEAP_END, HEAP_INIT, HEAP_START};
use super::types::{BlockHeader, BLOCK_MAGIC, INITIAL_HEAP_SIZE};
use crate::sys::serial;
use core::ptr::null_mut;
use core::sync::atomic::Ordering;

const GUARD_SIZE: usize = 16;

/// # Safety
/// Initializes heap with guard pages at boundaries. Guards detect overflow.
pub fn init() {
    if HEAP_INIT.load(Ordering::Relaxed) {
        return;
    }

    serial::println(b"[HEAP] Initializing kernel heap with guards...");

    let heap_phys_start: usize = 0xC00_0000;
    let heap_size = INITIAL_HEAP_SIZE;

    unsafe {
        let guard_low = heap_phys_start;
        let usable_start = heap_phys_start + GUARD_SIZE;
        let usable_end = heap_phys_start + heap_size - GUARD_SIZE;
        let guard_high = usable_end;

        write_guard(guard_low);
        write_guard(guard_high);

        HEAP_GUARD_LOW.store(guard_low as u64, Ordering::Release);
        HEAP_GUARD_HIGH.store(guard_high as u64, Ordering::Release);

        HEAP_START = usable_start;
        HEAP_END = usable_end;

        let usable_size = usable_end - usable_start;
        let initial_block = HEAP_START as *mut BlockHeader;
        (*initial_block).size = usable_size;
        (*initial_block).next = null_mut();
        (*initial_block).magic = BLOCK_MAGIC;

        FREE_LIST = initial_block;
    }

    HEAP_INIT.store(true, Ordering::SeqCst);

    serial::print(b"[HEAP] Heap at 0x");
    serial::print_hex(heap_phys_start as u64);
    serial::print(b" size: ");
    serial::print_dec((heap_size / 1024 / 1024) as u64);
    serial::println(b" MB (guarded)");
}
