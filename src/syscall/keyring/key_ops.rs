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
use super::types::KeySerial;
use alloc::string::String;
use alloc::vec::Vec;

pub fn update_payload(key: &mut Key, payload: Vec<u8>) {
    key.payload = payload;
}

pub fn revoke_key(key: &mut Key) {
    key.revoked = true;
}

pub fn set_timeout(key: &mut Key, timeout: u64) {
    key.expiry = Some(crate::sys::clock::system_time_secs() + timeout);
}

pub fn link_key(key: &mut Key, key_serial: KeySerial) {
    if !key.links.contains(&key_serial) {
        key.links.push(key_serial);
    }
}

pub fn unlink_key(key: &mut Key, key_serial: KeySerial) {
    key.links.retain(|&k| k != key_serial);
}

pub fn describe_key(key: &Key) -> String {
    alloc::format!(
        "{};{};{};{:08x};{}",
        key.key_type.as_str(),
        key.uid,
        key.gid,
        key.permissions,
        key.description
    )
}

pub fn has_permission(key: &Key, perm: u32, uid: u32, gid: u32) -> bool {
    if uid == key.uid {
        return key.permissions & (perm << 16) != 0;
    }
    if gid == key.gid {
        return key.permissions & (perm << 8) != 0;
    }
    key.permissions & perm != 0
}

pub fn set_permissions(key: &mut Key, permissions: u32) {
    key.permissions = permissions;
}

pub fn set_owner(key: &mut Key, uid: u32, gid: u32) {
    key.uid = uid;
    key.gid = gid;
}

pub fn clear_keyring(key: &mut Key) {
    key.links.clear();
}
