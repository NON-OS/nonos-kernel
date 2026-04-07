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
use crate::usercopy::{copy_to_user, write_user_value};
use crate::capabilities::Capability;
use crate::syscall::dispatch::util::require_capability;

/// Credential manipulation requires Admin capability - these are privileged operations
pub fn handle_setuid(uid: u32) -> SyscallResult {
    // Changing UID requires Admin capability
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    let _ = uid;
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_setgid(gid: u32) -> SyscallResult {
    // Changing GID requires Admin capability
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    let _ = gid;
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_setreuid(ruid: u32, euid: u32) -> SyscallResult {
    // Changing UID requires Admin capability
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    let _ = (ruid, euid);
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_setregid(rgid: u32, egid: u32) -> SyscallResult {
    // Changing GID requires Admin capability
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    let _ = (rgid, egid);
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_getresuid(ruid: u64, euid: u64, suid: u64) -> SyscallResult {
    if ruid == 0 || euid == 0 || suid == 0 {
        return errno(14);
    }

    let zero: u32 = 0;
    let _ = write_user_value(ruid, &zero);
    let _ = write_user_value(euid, &zero);
    let _ = write_user_value(suid, &zero);

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_setresuid(ruid: u32, euid: u32, suid: u32) -> SyscallResult {
    // Changing UID requires Admin capability
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    let _ = (ruid, euid, suid);
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_getresgid(rgid: u64, egid: u64, sgid: u64) -> SyscallResult {
    if rgid == 0 || egid == 0 || sgid == 0 {
        return errno(14);
    }

    let zero: u32 = 0;
    let _ = write_user_value(rgid, &zero);
    let _ = write_user_value(egid, &zero);
    let _ = write_user_value(sgid, &zero);

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_setresgid(rgid: u32, egid: u32, sgid: u32) -> SyscallResult {
    // Changing GID requires Admin capability
    if let Err(e) = require_capability(Capability::Admin) { return e; }
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
    // Changing groups requires Admin capability
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    let _ = (size, list);
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_capget(hdrp: u64, datap: u64) -> SyscallResult {
    use crate::usercopy::read_user_value;
    use core::sync::atomic::Ordering;
    if hdrp == 0 { return errno(14); }
    let version: u32 = read_user_value(hdrp).unwrap_or(0);
    if version != 0x20080522 && version != 0x20071026 && version != 0x19980330 {
        let _ = write_user_value(hdrp, &0x20080522u32);
        return errno(22);
    }
    if datap == 0 { return SyscallResult { value: 0, capability_consumed: false, audit_required: false }; }
    let pid: i32 = read_user_value(hdrp.wrapping_add(4)).unwrap_or(0);
    let target_pid = if pid <= 0 { crate::process::current_pid().unwrap_or(1) } else { pid as u32 };
    let caps_bits = crate::process::get_process_table().find_by_pid(target_pid)
        .map(|p| p.caps_bits.load(Ordering::Acquire)).unwrap_or(0);
    let eff = caps_bits as u32;
    let perm = caps_bits as u32;
    let inh = 0u32;
    let mut buf = [0u8; 24];
    buf[0..4].copy_from_slice(&eff.to_le_bytes());
    buf[4..8].copy_from_slice(&perm.to_le_bytes());
    buf[8..12].copy_from_slice(&inh.to_le_bytes());
    let _ = copy_to_user(datap, &buf);
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_capset(hdrp: u64, datap: u64) -> SyscallResult {
    use crate::usercopy::read_user_value;
    use core::sync::atomic::Ordering;
    if hdrp == 0 || datap == 0 { return errno(14); }
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    let pid: i32 = read_user_value(hdrp.wrapping_add(4)).unwrap_or(0);
    let target_pid = if pid <= 0 { crate::process::current_pid().unwrap_or(1) } else { pid as u32 };
    let eff: u32 = read_user_value(datap).unwrap_or(0);
    let pcb = match crate::process::get_process_table().find_by_pid(target_pid) {
        Some(p) => p,
        None => return errno(3),
    };
    pcb.caps_bits.store(eff as u64, Ordering::Release);
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
