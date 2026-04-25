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
use super::store::{allocate_key_serial, store_key};
use super::types::{KeySerial, KeyType, KEY_SPEC_PROCESS_KEYRING, KEY_SPEC_THREAD_KEYRING};
use super::types::{KEY_SPEC_SESSION_KEYRING, KEY_SPEC_USER_KEYRING};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

static THREAD_KEYRINGS: Mutex<BTreeMap<u64, KeySerial>> = Mutex::new(BTreeMap::new());
static PROCESS_KEYRINGS: Mutex<BTreeMap<u32, KeySerial>> = Mutex::new(BTreeMap::new());
static SESSION_KEYRINGS: Mutex<BTreeMap<u32, KeySerial>> = Mutex::new(BTreeMap::new());
static USER_KEYRINGS: Mutex<BTreeMap<u32, KeySerial>> = Mutex::new(BTreeMap::new());

pub fn resolve_special_keyring(spec: KeySerial, tid: u64, pid: u32, uid: u32) -> Option<KeySerial> {
    match spec {
        KEY_SPEC_THREAD_KEYRING => get_or_create_thread_keyring(tid),
        KEY_SPEC_PROCESS_KEYRING => get_or_create_process_keyring(pid),
        KEY_SPEC_SESSION_KEYRING => get_or_create_session_keyring(pid),
        KEY_SPEC_USER_KEYRING => get_or_create_user_keyring(uid),
        _ if spec > 0 => Some(spec),
        _ => None,
    }
}

pub fn get_or_create_thread_keyring(tid: u64) -> Option<KeySerial> {
    let mut map = THREAD_KEYRINGS.lock();
    if let Some(&serial) = map.get(&tid) {
        return Some(serial);
    }
    let serial = allocate_key_serial();
    let key = Key::new(serial, KeyType::Keyring, String::from("_tid"), Vec::new());
    store_key(key);
    map.insert(tid, serial);
    Some(serial)
}

pub fn get_or_create_process_keyring(pid: u32) -> Option<KeySerial> {
    let mut map = PROCESS_KEYRINGS.lock();
    if let Some(&serial) = map.get(&pid) {
        return Some(serial);
    }
    let serial = allocate_key_serial();
    let key = Key::new(serial, KeyType::Keyring, String::from("_pid"), Vec::new());
    store_key(key);
    map.insert(pid, serial);
    Some(serial)
}

pub fn get_or_create_session_keyring(pid: u32) -> Option<KeySerial> {
    let mut map = SESSION_KEYRINGS.lock();
    if let Some(&serial) = map.get(&pid) {
        return Some(serial);
    }
    let serial = allocate_key_serial();
    let key = Key::new(serial, KeyType::Keyring, String::from("_ses"), Vec::new());
    store_key(key);
    map.insert(pid, serial);
    Some(serial)
}

pub fn get_or_create_user_keyring(uid: u32) -> Option<KeySerial> {
    let mut map = USER_KEYRINGS.lock();
    if let Some(&serial) = map.get(&uid) {
        return Some(serial);
    }
    let serial = allocate_key_serial();
    let key = Key::new(serial, KeyType::Keyring, String::from("_uid"), Vec::new());
    store_key(key);
    map.insert(uid, serial);
    Some(serial)
}
