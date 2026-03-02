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
use crate::process::core::get_process_table;
use crate::shell::commands::utils::{format_num_simple, trim_bytes};

pub fn cmd_jobs() {
    print_line(b"Background Jobs:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    crate::shell::commands::builtins::list_jobs();
}

pub fn cmd_pidof(cmd: &[u8]) {
    let name = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        print_line(b"Usage: pidof <process_name>", COLOR_TEXT_DIM);
        return;
    };

    if name.is_empty() {
        print_line(b"pidof: process name required", COLOR_RED);
        return;
    }

    let table = get_process_table();
    let processes = table.get_all_processes();
    let mut found = false;

    let mut line = [0u8; 64];
    let mut pos = 0;

    for pcb in processes {
        let proc_name = pcb.name.lock();
        if proc_name.as_bytes() == name {
            if pos > 0 {
                line[pos] = b' ';
                pos += 1;
            }
            let len = format_num_simple(&mut line[pos..], pcb.pid as usize);
            pos += len;
            found = true;
        }
    }

    if found {
        print_line(&line[..pos], COLOR_TEXT);
    } else {
        print_line(b"(no matching process)", COLOR_TEXT_DIM);
    }
}

pub fn cmd_top() {
    use crate::sys::process;

    print_line(b"Real-time Process Monitor:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"PID   STATE     CPU%  MEM%  NAME", COLOR_TEXT_DIM);

    if process::is_init() {
        process::for_each_task(|id, state, name| {
            let mut line = [b' '; 64];

            let pid_len = format_num_simple(&mut line[0..], id as usize);
            for i in (0..pid_len).rev() {
                line[4 - pid_len + i + 1] = line[i];
                if i < 4 - pid_len {
                    line[i] = b' ';
                }
            }

            let state_str = process::state_str(state);
            let state_len = state_str.len().min(8);
            line[6..6+state_len].copy_from_slice(&state_str[..state_len]);

            line[15..19].copy_from_slice(b"0.0 ");
            line[21..25].copy_from_slice(b"0.0 ");

            let name_len = name.len().min(24);
            line[27..27+name_len].copy_from_slice(&name[..name_len]);

            let total_len = 27 + name_len;

            let color = match state {
                process::TaskState::Running => COLOR_GREEN,
                process::TaskState::Ready => COLOR_TEXT,
                process::TaskState::Sleeping => COLOR_YELLOW,
                _ => COLOR_TEXT_DIM,
            };

            print_line(&line[..total_len], color);
        });
    } else {
        print_line(b"    0 running  0.0  0.0  kernel_main", COLOR_GREEN);
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"(Press 'q' to exit in interactive mode)", COLOR_TEXT_DIM);
}
