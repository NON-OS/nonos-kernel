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

use crate::sys::serial;
use crate::boot::handoff::BootHandoffV1;

pub(crate) fn init_memory(handoff: &BootHandoffV1) {
    if handoff.mmap.entry_count == 0 || handoff.mmap.ptr == 0 {
        serial::println(b"[UKERNEL] No memory map, using defaults");
        init_defaults();
        return;
    }
    serial::println(b"[UKERNEL] Using memory map from handoff");
    let (start, end) = find_best_region(handoff);
    serial::print(b"[UKERNEL] Phys region: ");
    serial::print_hex(start);
    serial::print(b" - ");
    serial::print_hex(end);
    serial::println(b"");
    if crate::memory::phys::init(x86_64::PhysAddr::new(start), x86_64::PhysAddr::new(end)).is_err() {
        serial::println(b"[UKERNEL] phys::init failed");
        init_defaults();
        return;
    }
    if crate::memory::frame_alloc::init().is_err() {
        serial::println(b"[UKERNEL] frame_alloc::init failed");
    }
}

fn find_best_region(handoff: &BootHandoffV1) -> (u64, u64) {
    let regions = unsafe { handoff.mmap.usable_regions() };
    for (start, end) in regions {
        if start >= 0x100000 && (end - start) >= 0x1000000 { return (start, end); }
    }
    (0x100000, 0x40000000)
}

fn init_defaults() {
    let _ = crate::memory::phys::init(x86_64::PhysAddr::new(0x100000), x86_64::PhysAddr::new(0x40000000));
    let _ = crate::memory::frame_alloc::init();
}
