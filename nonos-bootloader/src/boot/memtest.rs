// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use uefi::prelude::*;
use uefi::table::boot::MemoryType;

const PATTERN_A: u64 = 0xAAAA_AAAA_AAAA_AAAA;
const PATTERN_5: u64 = 0x5555_5555_5555_5555;
const MIN_TEST_ADDR: u64 = 0x100000;

pub struct MemTestResult {
    pub total_mb: u64,
    pub usable_mb: u64,
    pub tested_regions: u32,
    pub errors_found: u32,
}

pub fn run_memory_test(st: &mut SystemTable<Boot>) -> MemTestResult {
    let _ = st.stdout().output_string(uefi::cstr16!("  [MEMTEST] Starting memory diagnostics...\r\n"));
    let bs = st.boot_services();
    let mmap_size = bs.memory_map_size().map_size + 2048;
    let mut result = MemTestResult { total_mb: 0, usable_mb: 0, tested_regions: 0, errors_found: 0 };

    if let Ok(buffer) = bs.allocate_pool(MemoryType::LOADER_DATA, mmap_size) {
        let slice = unsafe { core::slice::from_raw_parts_mut(buffer, mmap_size) };
        if let Ok(mmap) = bs.memory_map(slice) {
            for desc in mmap.entries() {
                result.total_mb += (desc.page_count * 4096) / (1024 * 1024);
                if desc.ty == MemoryType::CONVENTIONAL {
                    result.usable_mb += (desc.page_count * 4096) / (1024 * 1024);
                    if desc.phys_start >= MIN_TEST_ADDR && desc.page_count > 0 {
                        result.tested_regions += 1;
                        result.errors_found += test_region(desc.phys_start, desc.page_count);
                    }
                }
            }
        }
        let _ = bs.free_pool(buffer);
    }
    print_results(st, &result);
    result
}

fn test_region(addr: u64, pages: u64) -> u32 {
    let test_pages = pages.min(16);
    let mut errors = 0u32;
    for p in 0..test_pages {
        let ptr = (addr + p * 4096) as *mut u64;
        errors += test_location(ptr);
    }
    errors
}

fn test_location(ptr: *mut u64) -> u32 {
    unsafe {
        let backup = core::ptr::read_volatile(ptr);
        core::ptr::write_volatile(ptr, PATTERN_A);
        let r1 = core::ptr::read_volatile(ptr);
        core::ptr::write_volatile(ptr, PATTERN_5);
        let r2 = core::ptr::read_volatile(ptr);
        core::ptr::write_volatile(ptr, backup);
        if r1 != PATTERN_A || r2 != PATTERN_5 { 1 } else { 0 }
    }
}

fn print_results(st: &mut SystemTable<Boot>, r: &MemTestResult) {
    let _ = st.stdout().output_string(uefi::cstr16!("  [MEMTEST] Complete - "));
    super::util::print_u64(st, r.usable_mb);
    let _ = st.stdout().output_string(uefi::cstr16!(" MB usable, "));
    super::util::print_u64(st, r.errors_found as u64);
    let _ = st.stdout().output_string(uefi::cstr16!(" errors\r\n"));
}
