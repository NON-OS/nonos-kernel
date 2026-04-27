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
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

static NEXT_KEY_SERIAL: AtomicI32 = AtomicI32::new(1000);
static KEYS: Mutex<BTreeMap<KeySerial, Key>> = Mutex::new(BTreeMap::new());

pub fn allocate_key_serial() -> KeySerial {
    NEXT_KEY_SERIAL.fetch_add(1, Ordering::SeqCst)
}

pub fn store_key(key: Key) -> KeySerial {
    let serial = key.serial;
    KEYS.lock().insert(serial, key);
    serial
}

pub fn get_key(serial: KeySerial) -> Option<Key> {
    KEYS.lock().get(&serial).cloned()
}

pub fn get_key_mut<F, R>(serial: KeySerial, f: F) -> Option<R>
where
    F: FnOnce(&mut Key) -> R,
{
    KEYS.lock().get_mut(&serial).map(f)
}

pub fn remove_key(serial: KeySerial) -> Option<Key> {
    KEYS.lock().remove(&serial)
}

pub fn key_exists(serial: KeySerial) -> bool {
    KEYS.lock().contains_key(&serial)
}

pub fn key_count() -> usize {
    KEYS.lock().len()
}

pub fn get_all_keys() -> alloc::vec::Vec<KeySerial> {
    KEYS.lock().keys().copied().collect()
}

pub fn clear_all_keys() {
    KEYS.lock().clear();
}
