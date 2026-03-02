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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW};
use crate::mem::{heap, pmm};
use crate::shell::commands::utils::{format_size, format_num_simple, write_right_aligned, write_size_col};

pub fn cmd_mem() {
    print_line(b"Memory Status:", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"Mode:           ZeroState (RAM-only)", COLOR_GREEN);

    let (heap_used, _freed, _peak, heap_free) = heap::stats();
    let heap_total = heap_used + heap_free;

    let (pmm_total, pmm_used, pmm_free) = pmm::memory_stats();

    let mut line_buf = [0u8; 64];
    line_buf[..16].copy_from_slice(b"Heap Used:      ");
    let len = format_size(&mut line_buf[16..], heap_used);
    print_line(&line_buf[..16+len], COLOR_TEXT);

    line_buf[..16].copy_from_slice(b"Heap Free:      ");
    let len = format_size(&mut line_buf[16..], heap_free);
    print_line(&line_buf[..16+len], COLOR_GREEN);

    line_buf[..16].copy_from_slice(b"Heap Total:     ");
    let len = format_size(&mut line_buf[16..], heap_total);
    print_line(&line_buf[..16+len], COLOR_TEXT);

    print_line(b"", COLOR_TEXT);

    if pmm::is_init() {
        line_buf[..16].copy_from_slice(b"Phys Total:     ");
        let len = format_size(&mut line_buf[16..], pmm_total);
        print_line(&line_buf[..16+len], COLOR_TEXT);

        line_buf[..16].copy_from_slice(b"Phys Used:      ");
        let len = format_size(&mut line_buf[16..], pmm_used);
        print_line(&line_buf[..16+len], COLOR_TEXT);

        line_buf[..16].copy_from_slice(b"Phys Free:      ");
        let len = format_size(&mut line_buf[16..], pmm_free);
        print_line(&line_buf[..16+len], COLOR_GREEN);
    } else {
        print_line(b"PMM:            Not initialized", COLOR_YELLOW);
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"Swap:           DISABLED", COLOR_YELLOW);
    print_line(b"Persistence:    DISABLED (ZeroState)", COLOR_YELLOW);
    print_line(b"", COLOR_TEXT);
    print_line(b"All data in RAM - zeroed on shutdown", COLOR_GREEN);
}

pub fn cmd_df() {
    print_line(b"Filesystem Usage (RAM-based):", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"Filesystem  Size   Used   Avail  Use%", COLOR_TEXT_DIM);

    let (heap_used, _freed, _peak, heap_free) = heap::stats();
    let heap_total = heap_used + heap_free;

    let pct = if heap_total > 0 {
        (heap_used * 100) / heap_total
    } else {
        0
    };

    let mut line = [0u8; 64];
    line[..12].copy_from_slice(b"ramfs       ");
    let mut pos = 12;

    pos += write_size_col(&mut line[pos..], heap_total);
    pos += write_size_col(&mut line[pos..], heap_used);
    pos += write_size_col(&mut line[pos..], heap_free);
    let pct_len = format_num_simple(&mut line[pos..], pct);
    pos += pct_len;
    line[pos] = b'%';
    pos += 1;

    print_line(&line[..pos], COLOR_TEXT);
}

pub fn cmd_free() {
    print_line(b"Memory (KB):", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"          total    used    free", COLOR_TEXT_DIM);

    let (heap_used, _freed, _peak, heap_free) = heap::stats();
    let heap_total = heap_used + heap_free;

    let total_kb = heap_total / 1024;
    let used_kb = heap_used / 1024;
    let free_kb = heap_free / 1024;

    let mut line = [0u8; 48];
    line[..5].copy_from_slice(b"Heap:");
    let mut pos = 5;

    pos = write_right_aligned(&mut line, pos, total_kb, 9);
    pos = write_right_aligned(&mut line, pos, used_kb, 9);
    pos = write_right_aligned(&mut line, pos, free_kb, 9);
    print_line(&line[..pos], COLOR_TEXT);

    if pmm::is_init() {
        let (pmm_total, pmm_used, pmm_free) = pmm::memory_stats();
        let total_kb = pmm_total / 1024;
        let used_kb = pmm_used / 1024;
        let free_kb = pmm_free / 1024;

        let mut pline = [0u8; 48];
        pline[..5].copy_from_slice(b"Phys:");
        let mut pos = 5;
        pos = write_right_aligned(&mut pline, pos, total_kb, 9);
        pos = write_right_aligned(&mut pline, pos, used_kb, 9);
        pos = write_right_aligned(&mut pline, pos, free_kb, 9);
        print_line(&pline[..pos], COLOR_TEXT);
    }

    print_line(b"Swap:         0       0       0", COLOR_YELLOW);
}
