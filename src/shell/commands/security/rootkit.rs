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

/* scans kernel structures for tampering */

use crate::arch::x86_64::{gdt, idt};
use crate::display::framebuffer::{COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW};
use crate::shell::output::print_line;

pub fn cmd_rootkit_scan() {
    print_line(b"Rootkit Scanner:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    let mut threats = 0u32;

    print_line(b"[SCAN] Checking GDT...", COLOR_TEXT);
    if gdt::is_initialized() {
        print_line(b"[OK]   GDT: CLEAN", COLOR_GREEN);
    } else {
        print_line(b"[FAIL] GDT: TAMPERED", COLOR_RED);
        threats += 1;
    }

    print_line(b"[SCAN] Checking IDT...", COLOR_TEXT);
    if idt::verify_idt_integrity() {
        print_line(b"[OK]   IDT: CLEAN", COLOR_GREEN);
    } else {
        print_line(b"[FAIL] IDT: TAMPERED", COLOR_RED);
        threats += 1;
    }

    print_line(b"[SCAN] Checking process list...", COLOR_TEXT);
    let proc_table = crate::process::core::api::get_process_table();
    let procs = proc_table.get_all_processes();
    if !procs.is_empty() {
        print_line(b"[OK]   Process list: CLEAN", COLOR_GREEN);
    } else {
        print_line(b"[WARN] Process list: ANOMALY", COLOR_YELLOW);
    }

    print_line(b"", COLOR_TEXT);
    if threats == 0 {
        print_line(b"Scan Complete: NO THREATS DETECTED", COLOR_GREEN);
    } else {
        print_line(b"Scan Complete: THREATS FOUND", COLOR_RED);
    }
}
