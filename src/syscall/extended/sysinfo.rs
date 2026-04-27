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

use super::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_to_user, write_user_value};

pub fn handle_sysinfo(info: u64) -> SyscallResult {
    if info == 0 {
        return errno(14);
    }

    let uptime = crate::time::current_ticks() / 1000;
    let total_ram = crate::memory::phys::total_memory();
    let free_ram = crate::memory::boot_memory::available_memory();

    let mut sysinfo_buf = [0u8; 112];
    let uptime_val = uptime as i64;
    let procs: u16 = 1;
    let mem_unit: u32 = 1;

    sysinfo_buf[0..8].copy_from_slice(&uptime_val.to_ne_bytes());
    sysinfo_buf[32..40].copy_from_slice(&total_ram.to_ne_bytes());
    sysinfo_buf[40..48].copy_from_slice(&free_ram.to_ne_bytes());
    sysinfo_buf[80..82].copy_from_slice(&procs.to_ne_bytes());
    sysinfo_buf[104..108].copy_from_slice(&mem_unit.to_ne_bytes());

    if copy_to_user(info, &sysinfo_buf).is_err() {
        return errno(14);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

const SYSLOG_ACTION_CLOSE: i32 = 0;
const SYSLOG_ACTION_OPEN: i32 = 1;
const SYSLOG_ACTION_READ: i32 = 2;
const SYSLOG_ACTION_READ_ALL: i32 = 3;
const SYSLOG_ACTION_READ_CLEAR: i32 = 4;
const SYSLOG_ACTION_CLEAR: i32 = 5;
const SYSLOG_ACTION_CONSOLE_OFF: i32 = 6;
const SYSLOG_ACTION_CONSOLE_ON: i32 = 7;
const SYSLOG_ACTION_CONSOLE_LEVEL: i32 = 8;
const SYSLOG_ACTION_SIZE_UNREAD: i32 = 9;
const SYSLOG_ACTION_SIZE_BUFFER: i32 = 10;

pub fn handle_syslog(cmd: i32, buf: u64, len: i32) -> SyscallResult {
    match cmd {
        SYSLOG_ACTION_CLOSE | SYSLOG_ACTION_OPEN => {
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        SYSLOG_ACTION_READ | SYSLOG_ACTION_READ_ALL | SYSLOG_ACTION_READ_CLEAR => {
            if buf == 0 || len <= 0 {
                return errno(22);
            }
            let entries = crate::log::get_log_entries();
            let mut output = alloc::string::String::new();
            for entry in &entries {
                use core::fmt::Write;
                let _ = write!(output, "[{}] {}\n", entry.ts, entry.msg);
                if output.len() >= len as usize {
                    break;
                }
            }
            let bytes = output.as_bytes();
            let copy_len = bytes.len().min(len as usize);
            if copy_to_user(buf, &bytes[..copy_len]).is_err() {
                return errno(14);
            }
            if cmd == SYSLOG_ACTION_READ_CLEAR {
                crate::log::clear_log_buffer();
            }
            SyscallResult {
                value: copy_len as i64,
                capability_consumed: false,
                audit_required: false,
            }
        }
        SYSLOG_ACTION_CLEAR => {
            crate::log::clear_log_buffer();
            SyscallResult { value: 0, capability_consumed: false, audit_required: true }
        }
        SYSLOG_ACTION_CONSOLE_OFF | SYSLOG_ACTION_CONSOLE_ON | SYSLOG_ACTION_CONSOLE_LEVEL => {
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        SYSLOG_ACTION_SIZE_UNREAD | SYSLOG_ACTION_SIZE_BUFFER => {
            let count = crate::log::log_entry_count();
            SyscallResult {
                value: (count * 128) as i64,
                capability_consumed: false,
                audit_required: false,
            }
        }
        _ => errno(22),
    }
}

pub fn handle_getcpu(cpu: u64, node: u64, _tcache: u64) -> SyscallResult {
    if cpu != 0 {
        let cpu_id = crate::sched::current_cpu_id();
        if write_user_value(cpu, &cpu_id).is_err() {
            return errno(14);
        }
    }

    if node != 0 {
        let zero: u32 = 0;
        if write_user_value(node, &zero).is_err() {
            return errno(14);
        }
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_sethostname(name: u64, len: u64) -> SyscallResult {
    if name == 0 || len == 0 {
        return errno(14);
    }

    let hostname = match crate::syscall::dispatch::util::parse_string_from_user(name, len as usize)
    {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    match crate::sys::settings::set_hostname(&hostname) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: true, audit_required: true },
        Err(_) => errno(1),
    }
}

pub fn handle_setdomainname(name: u64, len: u64) -> SyscallResult {
    if name == 0 || len == 0 {
        return errno(14);
    }

    let domainname =
        match crate::syscall::dispatch::util::parse_string_from_user(name, len as usize) {
            Ok(s) => s,
            Err(_) => return errno(14),
        };

    match crate::sys::settings::set_domainname(&domainname) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: true, audit_required: true },
        Err(_) => errno(1),
    }
}
