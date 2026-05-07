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

use super::print_hex::print_hex_u64;

#[repr(C, packed)]
struct GdtPtrRaw {
    limit: u16,
    base: u64,
}

pub fn dump_gdt() {
    let mut p = GdtPtrRaw { limit: 0, base: 0 };
    // SAFETY: eK@nonos.systems — sgdt writes 10 bytes; the struct is
    // packed and 10 bytes long.
    unsafe {
        core::arch::asm!(
            "sgdt [{0}]",
            in(reg) &mut p,
            options(nostack, preserves_flags)
        );
    }
    let base = p.base;
    let limit = p.limit;

    crate::sys::serial::print(b"[GDT] base=");
    print_hex_u64(base);
    crate::sys::serial::print(b" limit=");
    print_hex_u64(limit as u64);
    crate::sys::serial::println(b"");

    let dump_descriptor = |idx: usize| {
        let off = idx * 8;
        if off + 8 > (limit as usize + 1) {
            return;
        }
        // SAFETY: eK@nonos.systems — base is the live GDT, idx*8 is in
        // range, descriptor is 8 bytes.
        let raw = unsafe { core::ptr::read_volatile((base + off as u64) as *const u64) };
        crate::sys::serial::print(b"[GDT] entry[");
        print_hex_u64(idx as u64);
        crate::sys::serial::print(b"] = ");
        print_hex_u64(raw);
        crate::sys::serial::println(b"");
    };

    dump_descriptor(0);
    dump_descriptor(1);
    dump_descriptor(2);
    dump_descriptor(3);
    dump_descriptor(4);
    dump_descriptor(5);
}
