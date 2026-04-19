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
use crate::usercopy::{copy_to_user, read_user_value, write_user_value};
use super::errno;

pub fn handle_getrusage(who: u64, usage: u64) -> SyscallResult {
    const RUSAGE_SELF: i32 = 0;
    const RUSAGE_CHILDREN: i32 = -1;
    const RUSAGE_THREAD: i32 = 1;

    if usage == 0 {
        return errno(14);
    }

    let who_val = who as i32;
    if who_val != RUSAGE_SELF && who_val != RUSAGE_CHILDREN && who_val != RUSAGE_THREAD {
        return errno(22);
    }

    let mut rusage_buf = [0u8; 144];

    let proc_opt = match who_val {
        RUSAGE_SELF | RUSAGE_THREAD => crate::process::current_process(),
        RUSAGE_CHILDREN => crate::process::current_process(),
        _ => None,
    };

    if let Some(proc) = proc_opt {
        let mem = proc.memory.lock();
        let resident_pages = mem.resident_pages.load(Ordering::Relaxed);
        let maxrss = (resident_pages as u64).saturating_mul(4) as i64;
        rusage_buf[16..24].copy_from_slice(&maxrss.to_ne_bytes());

        let utime_sec: i64 = (crate::time::current_ticks() / 1000) as i64;
        let utime_usec: i64 = ((crate::time::current_ticks() % 1000) * 1000) as i64;
        rusage_buf[0..8].copy_from_slice(&utime_sec.to_ne_bytes());
        rusage_buf[8..16].copy_from_slice(&utime_usec.to_ne_bytes());
    }

    if copy_to_user(usage, &rusage_buf).is_err() {
        return errno(14);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_uname(buf: u64) -> SyscallResult {
    if buf == 0 {
        return errno(14);
    }

    let mut utsname_buf = [0u8; 390];
    write_uname_field(&mut utsname_buf, 0, "NONOS");
    write_uname_field(&mut utsname_buf, 65, "zerostate");
    write_uname_field(&mut utsname_buf, 130, "0.1.0");
    write_uname_field(&mut utsname_buf, 195, "NONOS ZeroState Kernel");
    write_uname_field(&mut utsname_buf, 260, "x86_64");
    write_uname_field(&mut utsname_buf, 325, "(none)");

    if copy_to_user(buf, &utsname_buf).is_err() {
        return errno(14);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn write_uname_field(buf: &mut [u8], offset: usize, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(64);
    buf[offset..offset + len].copy_from_slice(&bytes[..len]);
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
        TCGETS => handle_tcgets(arg),
        TCSETS => handle_tcsets(fd, arg),
        TIOCGWINSZ => handle_tiocgwinsz(arg),
        TIOCSWINSZ => handle_tiocswinsz(fd, arg),
        FIONREAD => handle_fionread(fd, arg),
        FIONBIO => handle_fionbio(fd, arg),
        TIOCGPGRP => handle_tiocgpgrp(arg),
        TIOCSPGRP => handle_tiocspgrp(fd, arg),
        _ => errno(25),
    }
}

fn handle_tcgets(arg: u64) -> SyscallResult {
    if arg == 0 {
        return errno(14);
    }
    let mut termios = [0u8; 60];
    termios[0..4].copy_from_slice(&0x100u32.to_ne_bytes());
    termios[4..8].copy_from_slice(&0x05u32.to_ne_bytes());
    termios[8..12].copy_from_slice(&0xBFu32.to_ne_bytes());
    termios[12..16].copy_from_slice(&0x8A3Bu32.to_ne_bytes());
    if copy_to_user(arg, &termios).is_err() {
        return errno(14);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn handle_tiocgwinsz(arg: u64) -> SyscallResult {
    if arg == 0 {
        return errno(14);
    }
    let winsize: [u16; 4] = [25, 80, 0, 0];
    let mut buf = [0u8; 8];
    for (i, &v) in winsize.iter().enumerate() {
        buf[i * 2..i * 2 + 2].copy_from_slice(&v.to_ne_bytes());
    }
    if copy_to_user(arg, &buf).is_err() {
        return errno(14);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn handle_fionread(fd: i32, arg: u64) -> SyscallResult {
    if arg == 0 {
        return errno(14);
    }
    let available = match crate::fs::fd::fd_bytes_available(fd) {
        Ok(n) => n as i32,
        Err(_) => return errno(9),
    };
    if write_user_value(arg, &available).is_err() {
        return errno(14);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn handle_fionbio(fd: i32, arg: u64) -> SyscallResult {
    if arg == 0 {
        return errno(14);
    }
    let nonblock_val: i32 = match read_user_value(arg) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    match crate::fs::fd::fd_set_nonblocking(fd, nonblock_val != 0) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(_) => errno(9),
    }
}

fn handle_tiocgpgrp(arg: u64) -> SyscallResult {
    if arg == 0 {
        return errno(14);
    }
    let pgrp = crate::process::current_pid().unwrap_or(1) as i32;
    if write_user_value(arg, &pgrp).is_err() {
        return errno(14);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn handle_tcsets(fd: i32, arg: u64) -> SyscallResult {
    if arg == 0 {
        return errno(14);
    }
    let mut termios = [0u8; 60];
    if crate::usercopy::copy_from_user(arg, &mut termios).is_err() {
        return errno(14);
    }
    if let Err(_) = crate::tty::set_termios(fd, &termios) {
        return errno(25);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn handle_tiocswinsz(fd: i32, arg: u64) -> SyscallResult {
    if arg == 0 {
        return errno(14);
    }
    let rows: u16 = match read_user_value(arg) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let cols: u16 = match read_user_value(arg + 2) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    if let Err(_) = crate::tty::set_window_size(fd, rows, cols) {
        return errno(25);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn handle_tiocspgrp(fd: i32, arg: u64) -> SyscallResult {
    if arg == 0 {
        return errno(14);
    }
    let pgrp: i32 = match read_user_value(arg) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    if let Err(_) = crate::tty::set_foreground_pgrp(fd, pgrp) {
        return errno(25);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
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

    if let Some(proc) = crate::process::current_process() {
        let mut io_bitmap = proc.io_bitmap.lock();
        let end = (from + num) as usize;
        for port in (from as usize)..end {
            if port < io_bitmap.len() * 8 {
                let byte_idx = port / 8;
                let bit_idx = port % 8;
                if turn_on != 0 {
                    io_bitmap[byte_idx] &= !(1 << bit_idx);
                } else {
                    io_bitmap[byte_idx] |= 1 << bit_idx;
                }
            }
        }
    }

    SyscallResult { value: 0, capability_consumed: true, audit_required: true }
}

pub fn handle_ptrace(request: i64, pid: i64, addr: u64, data: u64) -> SyscallResult {
    crate::syscall::ptrace::handle_ptrace(request as u32, pid as u32, addr, data)
}
