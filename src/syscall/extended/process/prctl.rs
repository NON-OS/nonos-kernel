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
use crate::syscall::extended::errno;

pub fn handle_prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> SyscallResult {
    const PR_SET_NAME: i32 = 15;
    const PR_GET_NAME: i32 = 16;
    const PR_SET_DUMPABLE: i32 = 4;
    const PR_GET_DUMPABLE: i32 = 3;

    match option {
        PR_SET_NAME => {
            if arg2 == 0 {
                return errno(14);
            }
            let name = match crate::syscall::dispatch::util::parse_string_from_user(arg2, 16) {
                Ok(s) => s,
                Err(_) => return errno(14),
            };
            if let Some(proc) = crate::process::current_process() {
                proc.set_name(&name);
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        PR_GET_NAME => {
            if arg2 == 0 {
                return errno(14);
            }
            if let Some(proc) = crate::process::current_process() {
                let name = proc.name();
                let bytes = name.as_bytes();
                let copy_len = bytes.len().min(15);
                unsafe {
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), arg2 as *mut u8, copy_len);
                    core::ptr::write((arg2 + copy_len as u64) as *mut u8, 0);
                }
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        PR_SET_DUMPABLE => {
            let _ = arg2;
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        PR_GET_DUMPABLE => {
            SyscallResult { value: 1, capability_consumed: false, audit_required: false }
        }
        _ => {
            let _ = (arg3, arg4, arg5);
            errno(22)
        }
    }
}

pub fn handle_arch_prctl(code: i32, addr: u64) -> SyscallResult {
    const ARCH_SET_GS: i32 = 0x1001;
    const ARCH_SET_FS: i32 = 0x1002;
    const ARCH_GET_FS: i32 = 0x1003;
    const ARCH_GET_GS: i32 = 0x1004;

    match code {
        ARCH_SET_FS => {
            // SAFETY: Setting FS base for thread-local storage
            unsafe { crate::arch::x86_64::gdt::set_fs_base(addr); }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        ARCH_GET_FS => {
            // SAFETY: Reading FS base register
            let fs = unsafe { crate::arch::x86_64::gdt::get_fs_base() };
            unsafe {
                core::ptr::write(addr as *mut u64, fs);
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        ARCH_SET_GS => {
            // SAFETY: Setting GS base for thread-local storage
            unsafe { crate::arch::x86_64::gdt::set_gs_base(addr); }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        ARCH_GET_GS => {
            // SAFETY: Reading GS base register
            let gs = unsafe { crate::arch::x86_64::gdt::get_gs_base() };
            unsafe {
                core::ptr::write(addr as *mut u64, gs);
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        _ => errno(22),
    }
}

pub fn handle_set_tid_address(tidptr: u64) -> SyscallResult {
    if let Some(proc) = crate::process::current_process() {
        proc.set_clear_child_tid(tidptr);
    }

    let tid = crate::process::current_pid().unwrap_or(1);
    SyscallResult { value: tid as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_seccomp(operation: u32, flags: u32, args: u64) -> SyscallResult {
    let _ = (operation, flags, args);
    errno(38)
}

pub fn handle_getrandom(buf: u64, buflen: u64, flags: u32) -> SyscallResult {
    if buf == 0 {
        return errno(14);
    }

    let _ = flags;
    let len = buflen.min(256) as usize;

    let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
    crate::crypto::fill_random(slice);

    SyscallResult { value: len as i64, capability_consumed: false, audit_required: false }
}
