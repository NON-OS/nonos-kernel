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

use super::key_ops::*;
use super::special::resolve_special_keyring;
use super::store::get_key_mut;
use super::types::KeySerial;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::read_user_bytes;

pub fn keyctl_get_keyring_id(id: KeySerial, create: bool) -> SyscallResult {
    let tid = crate::process::current_tid() as u64;
    let pid = crate::process::current_pid().unwrap_or(1);
    let uid = crate::process::current_uid();
    if !create && id < 0 {
        return errno(2);
    }
    match resolve_special_keyring(id, tid, pid, uid) {
        Some(s) => {
            SyscallResult { value: s as i64, capability_consumed: false, audit_required: false }
        }
        None => errno(2),
    }
}

pub fn keyctl_join_session_keyring(_name: u64) -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(1);
    match super::special::get_or_create_session_keyring(pid) {
        Some(s) => {
            SyscallResult { value: s as i64, capability_consumed: false, audit_required: false }
        }
        None => errno(12),
    }
}

pub fn keyctl_update(key_id: KeySerial, payload_ptr: u64, plen: usize) -> SyscallResult {
    let payload = if payload_ptr != 0 && plen > 0 {
        match read_user_bytes(payload_ptr, plen) {
            Ok(p) => p,
            Err(_) => return errno(14),
        }
    } else {
        alloc::vec::Vec::new()
    };
    match get_key_mut(key_id, |k| update_payload(k, payload)) {
        Some(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        None => errno(2),
    }
}

pub fn keyctl_revoke(key_id: KeySerial) -> SyscallResult {
    match get_key_mut(key_id, |k| revoke_key(k)) {
        Some(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        None => errno(2),
    }
}

pub fn keyctl_chown(key_id: KeySerial, uid: u32, gid: u32) -> SyscallResult {
    match get_key_mut(key_id, |k| set_owner(k, uid, gid)) {
        Some(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        None => errno(2),
    }
}

pub fn keyctl_setperm(key_id: KeySerial, perm: u32) -> SyscallResult {
    match get_key_mut(key_id, |k| set_permissions(k, perm)) {
        Some(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        None => errno(2),
    }
}
