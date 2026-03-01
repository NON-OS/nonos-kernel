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

use core::sync::atomic::Ordering;

use crate::syscall::SyscallResult;
use super::errno;

pub fn handle_getrusage(_who: u64, usage: u64) -> SyscallResult {
    if usage == 0 {
        return errno(14);
    }

    unsafe {
        core::ptr::write_bytes(usage as *mut u8, 0, 144);
    }

    if let Some(proc) = crate::process::current_process() {
        let mem = proc.memory.lock();
        let resident_pages = mem.resident_pages.load(Ordering::Relaxed);

        unsafe {
            core::ptr::write((usage + 16) as *mut i64, (resident_pages * 4) as i64);
        }
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_uname(buf: u64) -> SyscallResult {
    if buf == 0 {
        return errno(14);
    }

    fn write_field(base: u64, offset: usize, s: &str) {
        let ptr = (base + offset as u64) as *mut u8;
        let bytes = s.as_bytes();
        let len = bytes.len().min(64);
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
            core::ptr::write(ptr.add(len), 0);
        }
    }

    unsafe {
        core::ptr::write_bytes(buf as *mut u8, 0, 390);
    }

    write_field(buf, 0, "NONOS");
    write_field(buf, 65, "zerostate");
    write_field(buf, 130, "0.1.0");
    write_field(buf, 195, "NONOS ZeroState Kernel");
    write_field(buf, 260, "x86_64");
    write_field(buf, 325, "(none)");

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_ioctl(fd: i32, request: u64, arg: u64) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    const FIONREAD: u64 = 0x541B;
    const FIONBIO: u64 = 0x5421;
    const TIOCGPGRP: u64 = 0x540F;
    const TIOCSPGRP: u64 = 0x5410;

    match request {
        TCGETS => {
            if arg == 0 {
                return errno(14);
            }
            unsafe {
                let termios = arg as *mut u8;
                core::ptr::write_bytes(termios, 0, 60);
                core::ptr::write(termios as *mut u32, 0x100);
                core::ptr::write((termios.add(4)) as *mut u32, 0x05);
                core::ptr::write((termios.add(8)) as *mut u32, 0xBF);
                core::ptr::write((termios.add(12)) as *mut u32, 0x8A3B);
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        TCSETS => {
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        TIOCGWINSZ => {
            if arg == 0 {
                return errno(14);
            }
            unsafe {
                let winsize = arg as *mut u16;
                core::ptr::write(winsize, 25);
                core::ptr::write(winsize.add(1), 80);
                core::ptr::write(winsize.add(2), 0);
                core::ptr::write(winsize.add(3), 0);
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        TIOCSWINSZ => {
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        FIONREAD => {
            if arg == 0 {
                return errno(14);
            }
            let available = match crate::fs::fd::fd_bytes_available(fd) {
                Ok(n) => n,
                Err(_) => return errno(9),
            };
            unsafe {
                core::ptr::write(arg as *mut i32, available as i32);
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        FIONBIO => {
            if arg == 0 {
                return errno(14);
            }
            let nonblock = unsafe { core::ptr::read(arg as *const i32) } != 0;
            match crate::fs::fd::fd_set_nonblocking(fd, nonblock) {
                Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
                Err(_) => errno(9),
            }
        }
        TIOCGPGRP => {
            if arg == 0 {
                return errno(14);
            }
            let pgrp = crate::process::current_pid().unwrap_or(1);
            unsafe {
                core::ptr::write(arg as *mut i32, pgrp as i32);
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        TIOCSPGRP => {
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        _ => errno(25),
    }
}

pub fn handle_iopl(level: i32) -> SyscallResult {
    if level < 0 || level > 3 {
        return errno(22);
    }

    SyscallResult { value: 0, capability_consumed: true, audit_required: true }
}

pub fn handle_ioperm(from: u64, num: u64, turn_on: i32) -> SyscallResult {
    if from > 0xFFFF || num == 0 || from.saturating_add(num) > 0x10000 {
        return errno(22);
    }

    let _ = turn_on;
    SyscallResult { value: 0, capability_consumed: true, audit_required: true }
}

pub fn handle_ptrace(request: i64, pid: i64, addr: u64, data: u64) -> SyscallResult {
    const PTRACE_TRACEME: i64 = 0;
    const PTRACE_PEEKTEXT: i64 = 1;
    const PTRACE_PEEKDATA: i64 = 2;
    const PTRACE_PEEKUSER: i64 = 3;
    const PTRACE_POKETEXT: i64 = 4;
    const PTRACE_POKEDATA: i64 = 5;
    const PTRACE_POKEUSER: i64 = 6;
    const PTRACE_CONT: i64 = 7;
    const PTRACE_KILL: i64 = 8;
    const PTRACE_SINGLESTEP: i64 = 9;
    const PTRACE_ATTACH: i64 = 16;
    const PTRACE_DETACH: i64 = 17;

    match request {
        PTRACE_TRACEME => {
            SyscallResult { value: 0, capability_consumed: false, audit_required: true }
        }
        PTRACE_ATTACH | PTRACE_DETACH => {
            let _ = (pid, addr, data);
            errno(1)
        }
        PTRACE_PEEKTEXT | PTRACE_PEEKDATA | PTRACE_PEEKUSER |
        PTRACE_POKETEXT | PTRACE_POKEDATA | PTRACE_POKEUSER |
        PTRACE_CONT | PTRACE_KILL | PTRACE_SINGLESTEP => {
            let _ = (pid, addr, data);
            errno(1)
        }
        _ => errno(22),
    }
}
