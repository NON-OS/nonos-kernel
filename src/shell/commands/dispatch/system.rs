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

use crate::shell::commands::{misc, power, system, hardware};
use crate::shell::commands::utils::starts_with;

pub fn try_dispatch_system(cmd: &[u8]) -> bool {
    if cmd == b"help" {
        misc::cmd_help();
    } else if cmd == b"info" || cmd == b"sysinfo" {
        system::cmd_info();
    } else if cmd == b"mem" || cmd == b"memory" {
        system::cmd_mem();
    } else if cmd == b"cpu" {
        system::cmd_cpu();
    } else if cmd == b"clear" || cmd == b"cls" {
        system::cmd_clear();
    } else if cmd == b"uptime" {
        system::cmd_uptime();
    } else if cmd == b"version" || cmd == b"ver" {
        system::cmd_version();
    } else if cmd == b"about" {
        misc::cmd_about();
    } else if cmd == b"date" || cmd == b"time" {
        system::cmd_date();
    } else if cmd == b"hostname" {
        system::cmd_hostname();
    } else if cmd == b"uname" || cmd == b"uname -a" {
        system::cmd_uname();
    } else if cmd == b"ps" || cmd == b"processes" {
        system::cmd_ps();
    } else if cmd == b"df" {
        system::cmd_df();
    } else if cmd == b"free" {
        system::cmd_free();
    } else if cmd == b"reboot" || cmd == b"restart" {
        power::cmd_reboot();
    } else if cmd == b"shutdown" || cmd == b"poweroff" {
        power::cmd_shutdown();
    } else if cmd == b"halt" {
        power::cmd_halt();
    } else if cmd == b"suspend" {
        power::cmd_suspend();
    } else if cmd == b"hibernate" {
        power::cmd_hibernate();
    } else if cmd == b"acpi" {
        power::cmd_acpi();
    } else if cmd == b"power" {
        power::cmd_power_status();
    } else if cmd == b"lspci" {
        hardware::cmd_lspci();
    } else if cmd == b"lscpu" {
        hardware::cmd_lscpu();
    } else if cmd == b"lsblk" {
        hardware::cmd_lsblk();
    } else if cmd == b"lsusb" {
        hardware::cmd_lsusb();
    } else if cmd == b"dmesg" || starts_with(cmd, b"dmesg ") {
        dispatch_dmesg(cmd);
    } else {
        return false;
    }
    true
}

fn dispatch_dmesg(cmd: &[u8]) {
    if cmd == b"dmesg" {
        hardware::cmd_dmesg();
        return;
    }

    let args_part = &cmd[6..];
    let mut args: heapless::Vec<&[u8], 8> = heapless::Vec::new();
    let mut start = 0;
    let mut in_word = false;

    for (i, &b) in args_part.iter().enumerate() {
        if b == b' ' || b == b'\t' {
            if in_word {
                let _ = args.push(&args_part[start..i]);
                in_word = false;
            }
        } else {
            if !in_word {
                start = i;
                in_word = true;
            }
        }
    }
    if in_word {
        let _ = args.push(&args_part[start..]);
    }

    let args_slice: alloc::vec::Vec<&[u8]> = args.iter().copied().collect();
    hardware::cmd_dmesg_with_args(&args_slice);
}
