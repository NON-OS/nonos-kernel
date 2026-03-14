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

use crate::syscall::SyscallResult;
use crate::usercopy::{copy_to_user, write_user_value};
use super::errno;

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

pub fn handle_syslog(cmd: i32, buf: u64, len: i32) -> SyscallResult {
    let _ = (cmd, buf, len);
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
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

    let hostname = match crate::syscall::dispatch::util::parse_string_from_user(name, len as usize) {
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

    let domainname = match crate::syscall::dispatch::util::parse_string_from_user(name, len as usize) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    match crate::sys::settings::set_domainname(&domainname) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: true, audit_required: true },
        Err(_) => errno(1),
    }
}
