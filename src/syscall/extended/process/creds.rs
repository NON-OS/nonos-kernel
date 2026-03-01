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

pub fn handle_setuid(uid: u32) -> SyscallResult {
    let _ = uid;
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_setgid(gid: u32) -> SyscallResult {
    let _ = gid;
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_setreuid(ruid: u32, euid: u32) -> SyscallResult {
    let _ = (ruid, euid);
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_setregid(rgid: u32, egid: u32) -> SyscallResult {
    let _ = (rgid, egid);
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_getresuid(ruid: u64, euid: u64, suid: u64) -> SyscallResult {
    if ruid == 0 || euid == 0 || suid == 0 {
        return errno(14);
    }

    unsafe {
        core::ptr::write(ruid as *mut u32, 0);
        core::ptr::write(euid as *mut u32, 0);
        core::ptr::write(suid as *mut u32, 0);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_setresuid(ruid: u32, euid: u32, suid: u32) -> SyscallResult {
    let _ = (ruid, euid, suid);
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_getresgid(rgid: u64, egid: u64, sgid: u64) -> SyscallResult {
    if rgid == 0 || egid == 0 || sgid == 0 {
        return errno(14);
    }

    unsafe {
        core::ptr::write(rgid as *mut u32, 0);
        core::ptr::write(egid as *mut u32, 0);
        core::ptr::write(sgid as *mut u32, 0);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_setresgid(rgid: u32, egid: u32, sgid: u32) -> SyscallResult {
    let _ = (rgid, egid, sgid);
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_setfsuid(fsuid: u32) -> SyscallResult {
    let _ = fsuid;
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_setfsgid(fsgid: u32) -> SyscallResult {
    let _ = fsgid;
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_getgroups(size: i32, _list: u64) -> SyscallResult {
    if size < 0 {
        return errno(22);
    }

    if size == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_setgroups(size: u64, list: u64) -> SyscallResult {
    let _ = (size, list);
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_capget(hdrp: u64, datap: u64) -> SyscallResult {
    if hdrp == 0 {
        return errno(14);
    }

    if datap != 0 {
        unsafe {
            core::ptr::write_bytes(datap as *mut u8, 0, 24);
        }
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_capset(hdrp: u64, datap: u64) -> SyscallResult {
    if hdrp == 0 || datap == 0 {
        return errno(14);
    }

    errno(1)
}
