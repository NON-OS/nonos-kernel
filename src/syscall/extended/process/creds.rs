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

pub fn handle_setuid(uid: u32) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    if let Some(pcb) = crate::process::current_process() {
        let mut creds = pcb.creds.lock();
        creds.uid = uid;
        creds.euid = uid;
        creds.suid = uid;
        creds.fsuid = uid;
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_setgid(gid: u32) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    if let Some(pcb) = crate::process::current_process() {
        let mut creds = pcb.creds.lock();
        creds.gid = gid;
        creds.egid = gid;
        creds.sgid = gid;
        creds.fsgid = gid;
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_setreuid(ruid: u32, euid: u32) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    if let Some(pcb) = crate::process::current_process() {
        let mut creds = pcb.creds.lock();
        if ruid != u32::MAX { creds.uid = ruid; }
        if euid != u32::MAX { creds.euid = euid; creds.fsuid = euid; }
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_setregid(rgid: u32, egid: u32) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    if let Some(pcb) = crate::process::current_process() {
        let mut creds = pcb.creds.lock();
        if rgid != u32::MAX { creds.gid = rgid; }
        if egid != u32::MAX { creds.egid = egid; creds.fsgid = egid; }
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_getresuid(ruid_ptr: u64, euid_ptr: u64, suid_ptr: u64) -> SyscallResult {
    if ruid_ptr == 0 || euid_ptr == 0 || suid_ptr == 0 {
        return errno(14);
    }
    let creds = crate::process::current_process()
        .map(|p| *p.creds.lock())
        .unwrap_or_default();
    let _ = write_user_value(ruid_ptr, &creds.uid);
    let _ = write_user_value(euid_ptr, &creds.euid);
    let _ = write_user_value(suid_ptr, &creds.suid);
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_setresuid(ruid: u32, euid: u32, suid: u32) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    if let Some(pcb) = crate::process::current_process() {
        let mut creds = pcb.creds.lock();
        if ruid != u32::MAX { creds.uid = ruid; }
        if euid != u32::MAX { creds.euid = euid; creds.fsuid = euid; }
        if suid != u32::MAX { creds.suid = suid; }
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_getresgid(rgid_ptr: u64, egid_ptr: u64, sgid_ptr: u64) -> SyscallResult {
    if rgid_ptr == 0 || egid_ptr == 0 || sgid_ptr == 0 { return errno(14); }
    let creds = crate::process::current_process()
        .map(|p| *p.creds.lock())
        .unwrap_or_default();
    let _ = write_user_value(rgid_ptr, &creds.gid);
    let _ = write_user_value(egid_ptr, &creds.egid);
    let _ = write_user_value(sgid_ptr, &creds.sgid);
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_setresgid(rgid: u32, egid: u32, sgid: u32) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    if let Some(pcb) = crate::process::current_process() {
        let mut creds = pcb.creds.lock();
        if rgid != u32::MAX { creds.gid = rgid; }
        if egid != u32::MAX { creds.egid = egid; creds.fsgid = egid; }
        if sgid != u32::MAX { creds.sgid = sgid; }
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_setfsuid(fsuid: u32) -> SyscallResult {
    let old_fsuid = crate::process::current_process()
        .map(|pcb| {
            let mut creds = pcb.creds.lock();
            let old = creds.fsuid;
            creds.fsuid = fsuid;
            old
        })
        .unwrap_or(0);
    SyscallResult { value: old_fsuid as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_setfsgid(fsgid: u32) -> SyscallResult {
    let old_fsgid = crate::process::current_process()
        .map(|pcb| {
            let mut creds = pcb.creds.lock();
            let old = creds.fsgid;
            creds.fsgid = fsgid;
            old
        })
        .unwrap_or(0);
    SyscallResult { value: old_fsgid as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_getgroups(size: i32, list: u64) -> SyscallResult {
    if size < 0 { return errno(22); }
    let creds = crate::process::current_process()
        .map(|p| *p.creds.lock())
        .unwrap_or_default();
    let ngroups = creds.ngroups;
    if size == 0 {
        return SyscallResult { value: ngroups as i64, capability_consumed: false, audit_required: false };
    }
    if (size as usize) < ngroups { return errno(22); }
    if list == 0 { return errno(14); }
    for i in 0..ngroups {
        if write_user_value(list + (i * 4) as u64, &creds.groups[i]).is_err() {
            return errno(14);
        }
    }
    SyscallResult { value: ngroups as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_setgroups(size: u64, list: u64) -> SyscallResult {
    use crate::usercopy::read_user_value;
    if let Err(e) = require_capability(Capability::Admin) { return e; }
    if size as usize > crate::process::core::types::NGROUPS_MAX { return errno(22); }
    if let Some(pcb) = crate::process::current_process() {
        let mut creds = pcb.creds.lock();
        creds.ngroups = size as usize;
        for i in 0..size as usize {
            creds.groups[i] = read_user_value(list + (i * 4) as u64).unwrap_or(0);
        }
    }
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
