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

use super::key_ops::{clear_keyring, describe_key, link_key, set_timeout, unlink_key};
use super::search::search_keyring;
use super::store::{get_key, get_key_mut, remove_key};
use super::types::KeySerial;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_string, write_user_bytes};

pub fn keyctl_describe(key_id: KeySerial, buf: u64, buflen: usize) -> SyscallResult {
    let key = match get_key(key_id) {
        Some(k) => k,
        None => return errno(2),
    };
    let desc = describe_key(&key);
    let bytes = desc.as_bytes();
    if buf != 0 && buflen > 0 {
        let to_copy = bytes.len().min(buflen);
        if write_user_bytes(buf, &bytes[..to_copy]).is_err() {
            return errno(14);
        }
    }
    SyscallResult {
        value: bytes.len() as i64 + 1,
        capability_consumed: false,
        audit_required: false,
    }
}

pub fn keyctl_clear(keyring_id: KeySerial) -> SyscallResult {
    match get_key_mut(keyring_id, |k| clear_keyring(k)) {
        Some(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        None => errno(2),
    }
}

pub fn keyctl_link(key_id: KeySerial, keyring_id: KeySerial) -> SyscallResult {
    if get_key(key_id).is_none() {
        return errno(2);
    }
    match get_key_mut(keyring_id, |kr| link_key(kr, key_id)) {
        Some(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        None => errno(2),
    }
}

pub fn keyctl_unlink(key_id: KeySerial, keyring_id: KeySerial) -> SyscallResult {
    match get_key_mut(keyring_id, |kr| unlink_key(kr, key_id)) {
        Some(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        None => errno(2),
    }
}

pub fn keyctl_search(
    keyring_id: KeySerial,
    type_ptr: u64,
    desc_ptr: u64,
    dest: KeySerial,
) -> SyscallResult {
    let type_str = match read_user_string(type_ptr, 32) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };
    let description = match read_user_string(desc_ptr, 256) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };
    match search_keyring(keyring_id, &type_str, &description) {
        Some(serial) => {
            if dest != 0 {
                get_key_mut(dest, |kr| link_key(kr, serial));
            }
            SyscallResult {
                value: serial as i64,
                capability_consumed: false,
                audit_required: false,
            }
        }
        None => errno(126),
    }
}

pub fn keyctl_read(key_id: KeySerial, buf: u64, buflen: usize) -> SyscallResult {
    let key = match get_key(key_id) {
        Some(k) => k,
        None => return errno(2),
    };
    if buf != 0 && buflen > 0 {
        let to_copy = key.payload.len().min(buflen);
        if write_user_bytes(buf, &key.payload[..to_copy]).is_err() {
            return errno(14);
        }
    }
    SyscallResult {
        value: key.payload.len() as i64,
        capability_consumed: false,
        audit_required: false,
    }
}

pub fn keyctl_set_timeout(key_id: KeySerial, timeout: u32) -> SyscallResult {
    match get_key_mut(key_id, |k| set_timeout(k, timeout as u64)) {
        Some(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        None => errno(2),
    }
}

pub fn keyctl_invalidate(key_id: KeySerial) -> SyscallResult {
    match remove_key(key_id) {
        Some(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        None => errno(2),
    }
}
