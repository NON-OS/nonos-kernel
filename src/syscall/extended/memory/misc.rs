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

use crate::syscall::SyscallResult;
use crate::syscall::extended::errno;

pub fn handle_msync(addr: u64, length: u64, flags: i32) -> SyscallResult {
    if addr & 0xFFF != 0 {
        return errno(22);
    }

    if length == 0 {
        return errno(22);
    }

    let _ = flags;
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_mincore(addr: u64, length: u64, vec: u64) -> SyscallResult {
    if addr & 0xFFF != 0 {
        return errno(22);
    }

    if vec == 0 {
        return errno(14);
    }

    let num_pages = (length + 4095) / 4096;

    unsafe {
        for i in 0..num_pages {
            core::ptr::write((vec + i) as *mut u8, 1);
        }
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_madvise(addr: u64, length: u64, advice: i32) -> SyscallResult {
    if addr & 0xFFF != 0 {
        return errno(22);
    }

    let _ = (length, advice);
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_memfd_create(name: u64, flags: u32) -> SyscallResult {
    let name_str = if name != 0 {
        match crate::syscall::dispatch::util::parse_string_from_user(name, 255) {
            Ok(s) => s,
            Err(_) => return errno(14),
        }
    } else {
        alloc::string::String::from("memfd")
    };

    match crate::fs::fd::create_memfd(&name_str, flags) {
        Ok(fd) => SyscallResult { value: fd as i64, capability_consumed: false, audit_required: false },
        Err(_) => errno(24),
    }
}
