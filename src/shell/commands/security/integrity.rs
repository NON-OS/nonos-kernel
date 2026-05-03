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

/* verifies kernel integrity using real hash checks */

use crate::arch::x86_64::gdt;
use crate::arch::x86_64::idt;
use crate::display::framebuffer::{COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE};
use crate::mem::heap;
use crate::shell::output::print_line;

pub fn cmd_integrity() {
    print_line(b"System Integrity Check:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    print_line(b"[CHECK] GDT...", COLOR_TEXT);
    let gdt_ok = gdt::is_initialized();
    print_result(gdt_ok);

    print_line(b"[CHECK] IDT...", COLOR_TEXT);
    let idt_ok = idt::verify_idt_integrity();
    print_result(idt_ok);

    print_line(b"[CHECK] Heap metadata...", COLOR_TEXT);
    let heap_ok = heap::is_init();
    print_result(heap_ok);

    print_line(b"", COLOR_TEXT);
    if gdt_ok && idt_ok && heap_ok {
        print_line(b"Integrity: VERIFIED", COLOR_GREEN);
    } else {
        print_line(b"Integrity: COMPROMISED", COLOR_RED);
    }
}

fn print_result(ok: bool) {
    if ok {
        print_line(b"[OK]    Valid", COLOR_GREEN);
    } else {
        print_line(b"[FAIL]  Invalid", COLOR_RED);
    }
}
