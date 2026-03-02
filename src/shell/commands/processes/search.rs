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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_RED};
use crate::process::core::{get_process_table, ProcessState};
use crate::shell::commands::utils::{format_num_simple, trim_bytes};

use super::util::contains_pattern;

pub fn cmd_pgrep(cmd: &[u8]) {
    let pattern = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        print_line(b"Usage: pgrep <pattern>", COLOR_TEXT_DIM);
        return;
    };

    if pattern.is_empty() {
        print_line(b"pgrep: pattern required", COLOR_RED);
        return;
    }

    print_line(b"Matching PIDs:", COLOR_TEXT_WHITE);

    let table = get_process_table();
    let processes = table.get_all_processes();
    let mut found = false;

    for pcb in processes {
        let name = pcb.name.lock();
        let name_bytes = name.as_bytes();

        if contains_pattern(name_bytes, pattern) {
            let mut line = [0u8; 48];
            let pid_len = format_num_simple(&mut line, pcb.pid as usize);
            line[pid_len] = b' ';
            let name_len = name_bytes.len().min(32);
            line[pid_len+1..pid_len+1+name_len].copy_from_slice(&name_bytes[..name_len]);
            print_line(&line[..pid_len+1+name_len], COLOR_TEXT);
            found = true;
        }
    }

    if !found {
        print_line(b"(no matching processes)", COLOR_TEXT_DIM);
    }
}

pub fn cmd_pkill(cmd: &[u8]) {
    let pattern = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        print_line(b"Usage: pkill <pattern>", COLOR_TEXT_DIM);
        return;
    };

    if pattern.is_empty() {
        print_line(b"pkill: pattern required", COLOR_RED);
        return;
    }

    let table = get_process_table();
    let processes = table.get_all_processes();
    let mut killed = 0u32;

    for pcb in processes {
        if pcb.pid == 0 {
            continue;
        }

        let name = pcb.name.lock();
        let name_bytes = name.as_bytes();

        if contains_pattern(name_bytes, pattern) {
            let mut state = pcb.state.lock();
            *state = ProcessState::Stopped;
            killed += 1;
        }
    }

    if killed > 0 {
        let mut line = [0u8; 48];
        line[..12].copy_from_slice(b"Terminated: ");
        let len = format_num_simple(&mut line[12..], killed as usize);
        line[12+len..12+len+10].copy_from_slice(b" processes");
        print_line(&line[..22+len], COLOR_GREEN);
    } else {
        print_line(b"pkill: no matching processes", COLOR_TEXT_DIM);
    }
}
