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

extern crate alloc;

use alloc::vec::Vec;

use crate::capabilities::Capability;
use crate::syscall::SyscallResult;
use super::{errno, require_capability, parse_string_from_user};

pub fn handle_read(fd: i32, buf: u64, count: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::IO) {
        return e;
    }

    if buf == 0 || count == 0 || count > 0x7FFF_FFFF {
        return errno(22);    }
    let ptr = buf as *mut u8;
    let n = crate::fs::read_file_descriptor(fd, ptr, count as usize);
    match n {
        Some(bytes) => SyscallResult { value: bytes as i64, capability_consumed: false, audit_required: false },
        None => errno(5),    }
}

pub fn handle_write(fd: i32, buf: u64, count: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::IO) {
        return e;
    }

    if buf == 0 || count == 0 || count > 0x7FFF_FFFF {
        return errno(22);    }
    let ptr = buf as *const u8;
    let n = crate::fs::write_file_descriptor(fd, ptr, count as usize);
    match n {
        Some(bytes) => SyscallResult { value: bytes as i64, capability_consumed: false, audit_required: false },
        None => errno(5),    }
}

pub fn handle_open(pathname: u64, flags: u64, mode: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::FileSystem) {
        return e;
    }

    if pathname == 0 {
        return errno(22);
    }
    let s = match parse_string_from_user(pathname, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),    };
    let mut tmp = Vec::with_capacity(s.len() + 1);
    tmp.extend_from_slice(s.as_bytes());
    tmp.push(0);

    let fd = crate::fs::open_file_syscall(tmp.as_ptr(), flags as i32, mode as u32);
    match fd {
        Some(n) => SyscallResult { value: n as i64, capability_consumed: false, audit_required: false },
        None => errno(2),    }
}

pub fn handle_close(fd: i32) -> SyscallResult {
    if let Err(e) = require_capability(Capability::FileSystem) {
        return e;
    }

    if crate::fs::close_file_descriptor(fd) {
        SyscallResult { value: 0, capability_consumed: false, audit_required: false }
    } else {
        errno(9)    }
}

pub fn handle_stat(pathname: u64, statbuf: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::FileSystem) {
        return e;
    }

    if pathname == 0 || statbuf == 0 {
        return errno(22);
    }
    let s = match parse_string_from_user(pathname, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let mut tmp = Vec::with_capacity(s.len() + 1);
    tmp.extend_from_slice(s.as_bytes());
    tmp.push(0);

    let ok = crate::fs::stat_file_syscall(tmp.as_ptr(), statbuf as *mut u8);
    if ok { SyscallResult { value: 0, capability_consumed: false, audit_required: false } } else { errno(2) }
}

pub fn handle_fstat(fd: i32, statbuf: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::FileSystem) {
        return e;
    }

    if statbuf == 0 {
        return errno(22);
    }
    let ok = crate::fs::fstat_file_syscall(fd, statbuf as *mut u8);
    if ok { SyscallResult { value: 0, capability_consumed: false, audit_required: false } } else { errno(9) }
}

pub fn handle_lseek(fd: i32, offset: i64, whence: i32) -> SyscallResult {
    if let Err(e) = require_capability(Capability::FileSystem) {
        return e;
    }

    match crate::fs::fd::lseek_syscall(fd, offset, whence) {
        Ok(new_off) => SyscallResult { value: new_off as i64, capability_consumed: false, audit_required: false },
        Err(_) => errno(22),
    }
}

pub fn handle_mkdir(pathname: u64, _mode: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::FileSystem) {
        return e;
    }

    if pathname == 0 {
        return errno(22);
    }
    let s = match parse_string_from_user(pathname, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    match crate::fs::nonos_vfs::get_vfs().ok_or("vfs").and_then(|vfs| vfs.mkdir_all(&s).map_err(|e| e.as_str())) {
        Ok(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(e) => {
            let code = if e == "File exists" { 17 } else { 5 };
            errno(code)
        }
    }
}

pub fn handle_rmdir(pathname: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::FileSystem) {
        return e;
    }

    if pathname == 0 {
        return errno(22);
    }
    let s = match parse_string_from_user(pathname, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    match crate::fs::nonos_vfs::get_vfs().ok_or("vfs").and_then(|vfs| vfs.rmdir(&s).map_err(|e| e.as_str())) {
        Ok(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(e) => {
            let code = match e {
                "Directory not empty" => 39,                "Directory not found" => 2,                 _ => 5,                                 };
            errno(code)
        }
    }
}

pub fn handle_unlink(pathname: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::FileSystem) {
        return e;
    }

    if pathname == 0 {
        return errno(22);
    }
    let s = match parse_string_from_user(pathname, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    match crate::fs::nonos_vfs::get_vfs().ok_or("vfs").and_then(|vfs| vfs.unlink(&s).map_err(|e| e.as_str())) {
        Ok(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(e) => {
            let code = if e == "Not found" || e == "File not found" { 2 } else { 5 };
            errno(code)
        }
    }
}

pub fn handle_rename(oldpath: u64, newpath: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::FileSystem) {
        return e;
    }

    if oldpath == 0 || newpath == 0 {
        return errno(22);
    }
    let old = match parse_string_from_user(oldpath, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let new = match parse_string_from_user(newpath, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    match crate::fs::nonos_vfs::get_vfs().ok_or("vfs").and_then(|vfs| vfs.rename(&old, &new).map_err(|e| e.as_str())) {
        Ok(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(_e) => errno(5),    }
}

pub fn handle_mmap(addr: u64, length: u64, prot: u64, _flags: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Memory) {
        return e;
    }

    if length == 0 {
        return errno(22);
    }
    let Some(proc) = crate::process::current_process() else {
        return errno(1);    };

    let mut page_flags = x86_64::structures::paging::PageTableFlags::PRESENT
        | x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE;

    if (prot & 0x2) != 0 {        page_flags |= x86_64::structures::paging::PageTableFlags::WRITABLE;
    }
    if (prot & 0x4) == 0 {        page_flags |= x86_64::structures::paging::PageTableFlags::NO_EXECUTE;
    }

    let start_addr = if addr != 0 { Some(x86_64::VirtAddr::new(addr)) } else { None };

    match proc.mmap(start_addr, length as usize, page_flags) {
        Ok(virt) => SyscallResult { value: virt.as_u64() as i64, capability_consumed: false, audit_required: false },
        Err(_) => errno(12),    }
}

pub fn handle_munmap(addr: u64, length: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Memory) {
        return e;
    }

    if addr == 0 || length == 0 {
        return errno(22);
    }
    let Some(proc) = crate::process::current_process() else {
        return errno(1);    };
    match proc.munmap(x86_64::VirtAddr::new(addr), length as usize) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(_) => errno(22),
    }
}
