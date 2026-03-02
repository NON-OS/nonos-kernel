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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_RED};
use crate::process::core::get_process_table;
use crate::process::scheduler::policy;
use crate::shell::commands::utils::{format_num_simple, trim_bytes};

use super::util::{parse_number, parse_signed_number, format_nice_value, split_first_word};

pub fn cmd_nice(cmd: &[u8]) {
    if cmd.len() <= 5 {
        print_line(b"nice - run command with modified priority", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);
        print_line(b"Usage: nice [-n priority] command", COLOR_TEXT_DIM);
        print_line(b"       nice -p <pid>  (show process priority)", COLOR_TEXT_DIM);
        print_line(b"  priority: -20 (highest) to 19 (lowest)", COLOR_TEXT_DIM);
        print_line(b"  default: 10 (lower priority)", COLOR_TEXT_DIM);

        let current_pid = crate::process::core::current_pid().unwrap_or(1);
        let nice = policy::get_nice(current_pid);
        let mut line = [0u8; 48];
        line[..24].copy_from_slice(b"Current shell priority: ");
        let len = format_nice_value(&mut line[24..], nice);
        print_line(&line[..24+len], COLOR_GREEN);
        return;
    }

    let args = trim_bytes(&cmd[5..]);

    if args.starts_with(b"-p ") {
        let pid_str = trim_bytes(&args[3..]);
        if let Some(pid) = parse_number(pid_str) {
            let table = get_process_table();
            if table.find_by_pid(pid as u32).is_some() {
                let nice = policy::get_nice(pid as u32);
                let mut line = [0u8; 48];
                line[..4].copy_from_slice(b"PID ");
                let plen = format_num_simple(&mut line[4..], pid as usize);
                line[4+plen..4+plen+8].copy_from_slice(b" nice = ");
                let nlen = format_nice_value(&mut line[12+plen..], nice);
                print_line(&line[..12+plen+nlen], COLOR_GREEN);
            } else {
                print_line(b"nice: process not found", COLOR_RED);
            }
        } else {
            print_line(b"nice: invalid PID", COLOR_RED);
        }
        return;
    }

    if args.starts_with(b"-n ") {
        let rest = trim_bytes(&args[3..]);
        let (nice_str, _cmd_rest) = split_first_word(rest);

        if let Some(nice) = parse_signed_number(nice_str) {
            if nice < -20 || nice > 19 {
                print_line(b"nice: priority must be -20 to 19", COLOR_RED);
                return;
            }

            let current_pid = crate::process::core::current_pid().unwrap_or(1);
            match policy::set_nice(current_pid, nice) {
                Ok(()) => {
                    let mut line = [0u8; 48];
                    line[..18].copy_from_slice(b"Priority set to: ");
                    let len = format_nice_value(&mut line[18..], nice);
                    print_line(&line[..18+len], COLOR_GREEN);
                }
                Err(e) => {
                    let mut line = [0u8; 64];
                    line[..7].copy_from_slice(b"nice: ");
                    let elen = e.len().min(50);
                    line[7..7+elen].copy_from_slice(&e.as_bytes()[..elen]);
                    print_line(&line[..7+elen], COLOR_RED);
                }
            }
        } else {
            print_line(b"nice: invalid priority value", COLOR_RED);
        }
    } else {
        print_line(b"nice: use -n to specify priority", COLOR_TEXT_DIM);
    }
}

pub fn cmd_renice(cmd: &[u8]) {
    if cmd.len() <= 7 {
        print_line(b"renice - alter priority of running process", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);
        print_line(b"Usage: renice <priority> -p <pid>", COLOR_TEXT_DIM);
        print_line(b"       renice <priority> <pid>", COLOR_TEXT_DIM);
        print_line(b"  priority: -20 (highest) to 19 (lowest)", COLOR_TEXT_DIM);
        return;
    }

    let args = trim_bytes(&cmd[7..]);
    let (nice_str, rest) = split_first_word(args);

    let nice = match parse_signed_number(nice_str) {
        Some(n) => n,
        None => {
            print_line(b"renice: invalid priority value", COLOR_RED);
            return;
        }
    };

    if nice < -20 || nice > 19 {
        print_line(b"renice: priority must be -20 to 19", COLOR_RED);
        return;
    }

    let rest = trim_bytes(rest);
    let pid_str = if rest.starts_with(b"-p ") {
        trim_bytes(&rest[3..])
    } else {
        rest
    };

    let pid = match parse_number(pid_str) {
        Some(p) => p as u32,
        None => {
            print_line(b"renice: invalid PID", COLOR_RED);
            return;
        }
    };

    if pid == 0 {
        print_line(b"renice: cannot modify kernel process", COLOR_RED);
        return;
    }

    let table = get_process_table();
    if table.find_by_pid(pid).is_none() {
        print_line(b"renice: process not found", COLOR_RED);
        return;
    }

    let old_nice = policy::get_nice(pid);

    match policy::set_nice(pid, nice) {
        Ok(()) => {
            let mut line = [0u8; 64];
            line[..4].copy_from_slice(b"PID ");
            let mut pos = 4;
            pos += format_num_simple(&mut line[pos..], pid as usize);
            line[pos..pos+7].copy_from_slice(b": nice ");
            pos += 7;
            pos += format_nice_value(&mut line[pos..], old_nice);
            line[pos..pos+4].copy_from_slice(b" -> ");
            pos += 4;
            pos += format_nice_value(&mut line[pos..], nice);
            print_line(&line[..pos], COLOR_GREEN);
        }
        Err(e) => {
            let mut line = [0u8; 64];
            line[..9].copy_from_slice(b"renice: ");
            let elen = e.len().min(50);
            line[9..9+elen].copy_from_slice(&e.as_bytes()[..elen]);
            print_line(&line[..9+elen], COLOR_RED);
        }
    }
}
