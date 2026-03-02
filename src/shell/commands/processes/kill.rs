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
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED};
use crate::process::core::{get_process_table, ProcessState};
use crate::shell::commands::utils::{format_num_simple, trim_bytes};

use super::util::parse_number;

pub fn cmd_kill(cmd: &[u8]) {
    let args = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: kill <pid> [signal]", COLOR_TEXT_DIM);
        print_line(b"Signals: TERM (15), KILL (9), HUP (1)", COLOR_TEXT_DIM);
        return;
    };

    let (pid_str, signal) = parse_kill_args(args);

    let pid = match parse_number(pid_str) {
        Some(p) => p,
        None => {
            print_line(b"kill: invalid PID", COLOR_RED);
            return;
        }
    };

    if pid == 0 {
        print_line(b"kill: cannot kill PID 0 (kernel)", COLOR_RED);
        return;
    }

    let table = get_process_table();

    match table.find_by_pid(pid as u32) {
        Some(pcb) => {
            let name = pcb.name.lock().clone();

            {
                let mut state = pcb.state.lock();
                match signal {
                    9 => {
                        *state = ProcessState::Zombie(0);
                        let mut line = [0u8; 64];
                        line[..8].copy_from_slice(b"Killed: ");
                        let name_bytes = name.as_bytes();
                        let name_len = name_bytes.len().min(40);
                        line[8..8+name_len].copy_from_slice(&name_bytes[..name_len]);
                        line[8+name_len..8+name_len+7].copy_from_slice(b" (PID ");
                        let pid_len = format_num_simple(&mut line[15+name_len..], pid as usize);
                        line[15+name_len+pid_len] = b')';
                        print_line(&line[..16+name_len+pid_len], COLOR_YELLOW);
                    }
                    15 => {
                        *state = ProcessState::Stopped;
                        let mut line = [0u8; 64];
                        line[..13].copy_from_slice(b"Terminated: ");
                        let name_bytes = name.as_bytes();
                        let name_len = name_bytes.len().min(35);
                        line[13..13+name_len].copy_from_slice(&name_bytes[..name_len]);
                        print_line(&line[..13+name_len], COLOR_GREEN);
                    }
                    1 => {
                        print_line(b"Sent SIGHUP to process", COLOR_TEXT);
                    }
                    19 => {
                        *state = ProcessState::Stopped;
                        print_line(b"Process stopped (SIGSTOP)", COLOR_YELLOW);
                    }
                    18 => {
                        if *state == ProcessState::Stopped {
                            *state = ProcessState::Running;
                            print_line(b"Process continued (SIGCONT)", COLOR_GREEN);
                        }
                    }
                    _ => {
                        let mut line = [0u8; 48];
                        line[..13].copy_from_slice(b"Sent signal ");
                        let sig_len = format_num_simple(&mut line[13..], signal as usize);
                        line[13+sig_len..13+sig_len+12].copy_from_slice(b" to process");
                        print_line(&line[..25+sig_len], COLOR_TEXT);
                    }
                }
            }
        }
        None => {
            let mut line = [0u8; 48];
            line[..21].copy_from_slice(b"kill: no process PID ");
            let len = format_num_simple(&mut line[21..], pid as usize);
            print_line(&line[..21+len], COLOR_RED);
        }
    }
}

fn parse_kill_args(args: &[u8]) -> (&[u8], u32) {
    if args.starts_with(b"-9 ") || args.starts_with(b"-KILL ") {
        let start = if args.starts_with(b"-9 ") { 3 } else { 6 };
        return (trim_bytes(&args[start..]), 9);
    }

    if args.starts_with(b"-15 ") || args.starts_with(b"-TERM ") {
        let start = if args.starts_with(b"-15 ") { 4 } else { 6 };
        return (trim_bytes(&args[start..]), 15);
    }

    if args.starts_with(b"-1 ") || args.starts_with(b"-HUP ") {
        let start = if args.starts_with(b"-1 ") { 3 } else { 5 };
        return (trim_bytes(&args[start..]), 1);
    }

    if args.starts_with(b"-STOP ") {
        return (trim_bytes(&args[6..]), 19);
    }

    if args.starts_with(b"-CONT ") {
        return (trim_bytes(&args[6..]), 18);
    }

    (args, 15)
}
