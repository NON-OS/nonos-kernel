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
use super::errno;

pub fn handle_gettimeofday(tv: u64, _tz: u64) -> SyscallResult {
    if tv != 0 {
        let ms = crate::time::timestamp_millis();
        let tv_sec = ms / 1000;
        let tv_usec = (ms % 1000) * 1000;

        unsafe {
            core::ptr::write(tv as *mut i64, tv_sec as i64);
            core::ptr::write((tv + 8) as *mut i64, tv_usec as i64);
        }
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_settimeofday(tv: u64, _tz: u64) -> SyscallResult {
    if tv == 0 {
        return errno(14);
    }

    errno(1)
}


pub fn handle_clock_nanosleep(clock_id: u64, flags: u64, request: u64, remain: u64) -> SyscallResult {
    const TIMER_ABSTIME: u64 = 1;

    if request == 0 {
        return errno(14);
    }

    let ts_sec = unsafe { core::ptr::read(request as *const i64) };
    let ts_nsec = unsafe { core::ptr::read((request + 8) as *const i64) };

    if ts_sec < 0 || ts_nsec < 0 || ts_nsec >= 1_000_000_000 {
        return errno(22);
    }

    let target_ns = if (flags & TIMER_ABSTIME) != 0 {
        (ts_sec as u64) * 1_000_000_000 + (ts_nsec as u64)
    } else {
        crate::time::now_ns() + (ts_sec as u64) * 1_000_000_000 + (ts_nsec as u64)
    };

    let _ = clock_id;
    let pid = crate::process::current_pid().unwrap_or(0);
    let wake_time_ms = target_ns / 1_000_000;
    crate::sched::scheduler::sleep_until(pid, wake_time_ms);

    if remain != 0 {
        unsafe {
            core::ptr::write(remain as *mut i64, 0);
            core::ptr::write((remain + 8) as *mut i64, 0);
        }
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_times(buf: u64) -> SyscallResult {
    if buf == 0 {
        return errno(14);
    }

    let ticks = crate::time::current_ticks();

    unsafe {
        core::ptr::write(buf as *mut i64, ticks as i64);
        core::ptr::write((buf + 8) as *mut i64, 0);
        core::ptr::write((buf + 16) as *mut i64, 0);
        core::ptr::write((buf + 24) as *mut i64, 0);
    }

    SyscallResult { value: ticks as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_getrlimit(resource: u32, rlim: u64) -> SyscallResult {
    if rlim == 0 {
        return errno(14);
    }

    let (soft, hard) = match resource {
        0 => (0x7FFFFFFF, 0x7FFFFFFF),
        1 => (0x7FFFFFFF, 0x7FFFFFFF),
        2 => (0x7FFFFFFF, 0x7FFFFFFF),
        3 => (8 * 1024 * 1024, 8 * 1024 * 1024),
        4 => (0, 0x7FFFFFFF),
        5 => (0x7FFFFFFF, 0x7FFFFFFF),
        6 => (4096, 4096),
        7 => (1024, 4096),
        _ => (0x7FFFFFFF, 0x7FFFFFFF),
    };

    unsafe {
        core::ptr::write(rlim as *mut u64, soft);
        core::ptr::write((rlim + 8) as *mut u64, hard);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_setrlimit(resource: u32, rlim: u64) -> SyscallResult {
    if rlim == 0 {
        return errno(14);
    }

    let _ = resource;
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_prlimit64(pid: i32, resource: u32, new_limit: u64, old_limit: u64) -> SyscallResult {
    if old_limit != 0 {
        let result = handle_getrlimit(resource, old_limit);
        if result.value < 0 {
            return result;
        }
    }

    if new_limit != 0 {
        let _ = pid;
        let result = handle_setrlimit(resource, new_limit);
        if result.value < 0 {
            return result;
        }
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_sysinfo(info: u64) -> SyscallResult {
    if info == 0 {
        return errno(14);
    }

    let uptime = crate::time::current_ticks() / 1000;
    let total_ram = crate::memory::phys::total_memory();
    let free_ram = crate::memory::boot_memory::available_memory();

    unsafe {
        let ptr = info as *mut u8;
        core::ptr::write_bytes(ptr, 0, 112);

        core::ptr::write((ptr.add(0)) as *mut i64, uptime as i64);
        core::ptr::write((ptr.add(32)) as *mut u64, total_ram);
        core::ptr::write((ptr.add(40)) as *mut u64, free_ram);
        core::ptr::write((ptr.add(48)) as *mut u64, 0);
        core::ptr::write((ptr.add(56)) as *mut u64, 0);
        core::ptr::write((ptr.add(64)) as *mut u64, 0);
        core::ptr::write((ptr.add(72)) as *mut u64, 0);
        core::ptr::write((ptr.add(80)) as *mut u16, 1);
        core::ptr::write((ptr.add(104)) as *mut u32, 1);
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
        unsafe {
            core::ptr::write(cpu as *mut u32, cpu_id);
        }
    }

    if node != 0 {
        unsafe {
            core::ptr::write(node as *mut u32, 0);
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
