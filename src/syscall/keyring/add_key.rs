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

use super::key::Key;
use super::key_ops::link_key;
use super::special::resolve_special_keyring;
use super::store::{allocate_key_serial, get_key_mut, store_key};
use super::types::{KeySerial, KeyType};
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_bytes, read_user_string};
use alloc::vec::Vec;

pub fn handle_add_key(
    type_ptr: u64,
    desc_ptr: u64,
    payload_ptr: u64,
    plen: u64,
    keyring: KeySerial,
) -> SyscallResult {
    let type_str = match read_user_string(type_ptr, 32) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };
    let key_type = match KeyType::from_str(&type_str) {
        Some(t) => t,
        None => return errno(22),
    };
    let description = match read_user_string(desc_ptr, 256) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };
    let payload = if payload_ptr != 0 && plen > 0 {
        match read_user_bytes(payload_ptr, plen as usize) {
            Ok(p) => p,
            Err(_) => return errno(14),
        }
    } else {
        Vec::new()
    };
    let tid = crate::process::current_tid() as u64;
    let pid = crate::process::current_pid().unwrap_or(1);
    let uid = crate::process::current_uid();
    let keyring_serial = match resolve_special_keyring(keyring, tid, pid, uid) {
        Some(s) => s,
        None => return errno(22),
    };
    let serial = allocate_key_serial();
    let key = Key::new(serial, key_type, description, payload);
    store_key(key);
    get_key_mut(keyring_serial, |kr| link_key(kr, serial));
    SyscallResult { value: serial as i64, capability_consumed: false, audit_required: true }
}
