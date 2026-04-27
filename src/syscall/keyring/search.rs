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

use super::store::get_key;
use super::types::KeySerial;
use alloc::vec::Vec;

pub fn search_keyring(
    keyring_serial: KeySerial,
    key_type: &str,
    description: &str,
) -> Option<KeySerial> {
    let keyring = get_key(keyring_serial)?;
    for &linked in &keyring.links {
        if let Some(key) = get_key(linked) {
            if key.key_type.as_str() == key_type && key.description == description && key.is_valid()
            {
                return Some(linked);
            }
        }
    }
    None
}

pub fn search_keyring_recursive(
    keyring_serial: KeySerial,
    key_type: &str,
    description: &str,
    visited: &mut Vec<KeySerial>,
) -> Option<KeySerial> {
    if visited.contains(&keyring_serial) {
        return None;
    }
    visited.push(keyring_serial);
    let keyring = get_key(keyring_serial)?;
    for &linked in &keyring.links {
        if let Some(key) = get_key(linked) {
            if key.key_type.as_str() == key_type && key.description == description && key.is_valid()
            {
                return Some(linked);
            }
            if key.is_keyring() {
                if let Some(found) =
                    search_keyring_recursive(linked, key_type, description, visited)
                {
                    return Some(found);
                }
            }
        }
    }
    None
}

pub fn list_keyring_keys(keyring_serial: KeySerial) -> Vec<KeySerial> {
    get_key(keyring_serial).map(|k| k.links.clone()).unwrap_or_default()
}

pub fn keyring_contains(keyring_serial: KeySerial, key_serial: KeySerial) -> bool {
    get_key(keyring_serial).map(|k| k.links.contains(&key_serial)).unwrap_or(false)
}
