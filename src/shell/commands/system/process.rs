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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED};
use crate::sys::{process, timer};
use crate::mem::heap;
use crate::input::usb_hid;
use crate::shell::commands::utils::format_num_simple;

pub fn cmd_ps() {
    print_line(b"Process List:", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"PID  STATE     NAME", COLOR_TEXT_DIM);

    if process::is_init() {
        process::for_each_task(|id, state, name| {
            let mut line = [b' '; 48];

            let pid_len = format_num_simple(&mut line[0..], id as usize);
            if pid_len < 3 {
                for i in (0..pid_len).rev() {
                    line[3 - pid_len + i] = line[i];
                    if i < 3 - pid_len {
                        line[i] = b' ';
                    }
                }
            }

            let state_str = process::state_str(state);
            let state_len = state_str.len().min(8);
            line[5..5+state_len].copy_from_slice(&state_str[..state_len]);

            let name_len = name.len().min(32);
            line[14..14+name_len].copy_from_slice(&name[..name_len]);

            let total_len = 14 + name_len;

            let color = match state {
                process::TaskState::Running => COLOR_GREEN,
                process::TaskState::Ready => COLOR_TEXT,
                process::TaskState::Sleeping => COLOR_YELLOW,
                _ => COLOR_TEXT_DIM,
            };

            print_line(&line[..total_len], color);
        });

        let count = process::task_count();
        let mut count_line = [0u8; 32];
        count_line[..8].copy_from_slice(b"Total:  ");
        let len = format_num_simple(&mut count_line[8..], count as usize);
        count_line[8+len..8+len+7].copy_from_slice(b" tasks");
        print_line(&count_line[..8+len+7], COLOR_TEXT_DIM);
    } else {
        print_line(b"  0  running  kernel_main", COLOR_GREEN);
        print_line(b"(scheduler not initialized)", COLOR_TEXT_DIM);
    }
}

pub fn cmd_monitor() {
    print_line(b"System Monitor:", COLOR_TEXT_WHITE);
    print_line(b"===================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    let (heap_used, _freed, _peak, heap_free) = heap::stats();
    let heap_total = heap_used + heap_free;
    let mem_pct = if heap_total > 0 { (heap_used * 100) / heap_total } else { 0 };
    draw_usage_bar(b"Memory:        ", mem_pct);

    print_line(b"Network I/O:   [----------]   0%", COLOR_YELLOW);

    draw_usage_bar(b"RAM Storage:   ", mem_pct);

    print_line(b"", COLOR_TEXT);

    if timer::is_init() {
        let mut uptime_buf = [0u8; 8];
        timer::format_uptime(&mut uptime_buf);
        let mut line = [0u8; 32];
        line[..10].copy_from_slice(b"Uptime:    ");
        line[10..18].copy_from_slice(&uptime_buf);
        print_line(&line[..18], COLOR_TEXT);
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"Subsystems:", COLOR_TEXT_WHITE);
    if usb_hid::is_available() {
        print_line(b"  USB HID:   ACTIVE", COLOR_GREEN);
    } else {
        print_line(b"  USB HID:   PS/2 mode", COLOR_YELLOW);
    }
    if heap::is_init() {
        print_line(b"  Heap:      ACTIVE", COLOR_GREEN);
    }
    if timer::is_init() {
        print_line(b"  Timer:     ACTIVE", COLOR_GREEN);
    }
}

fn draw_usage_bar(label: &[u8], pct: usize) {
    let mut line = [0u8; 48];
    let label_len = label.len().min(15);
    line[..label_len].copy_from_slice(&label[..label_len]);

    let mut pos = 15;
    line[pos] = b'[';
    pos += 1;

    let filled = (pct + 9) / 10;
    for i in 0..10 {
        line[pos + i] = if i < filled { b'#' } else { b'-' };
    }
    pos += 10;
    line[pos] = b']';
    pos += 1;

    line[pos] = b' ';
    pos += 1;
    if pct < 10 {
        line[pos] = b' ';
        pos += 1;
    }
    let pct_len = format_num_simple(&mut line[pos..], pct);
    pos += pct_len;
    line[pos] = b'%';
    pos += 1;

    let color = if pct > 80 { COLOR_RED } else if pct > 50 { COLOR_YELLOW } else { COLOR_GREEN };
    print_line(&line[..pos], color);
}
