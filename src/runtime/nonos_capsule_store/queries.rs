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

use alloc::vec::Vec;

use super::types::CapsuleMetadata;
use super::state::CAPSULE_STORE;

pub fn list_available() -> Vec<CapsuleMetadata> {
    let lock = CAPSULE_STORE.lock();
    match lock.as_ref() {
        Some(store) => store.available.read().values().cloned().collect(),
        None => Vec::new(),
    }
}

pub fn list_installed() -> Vec<CapsuleMetadata> {
    let lock = CAPSULE_STORE.lock();
    match lock.as_ref() {
        Some(store) => store.installed.read().values().map(|c| c.metadata.clone()).collect(),
        None => Vec::new(),
    }
}

pub fn get_capsule(id: &[u8; 32]) -> Option<CapsuleMetadata> {
    let lock = CAPSULE_STORE.lock();
    match lock.as_ref() {
        Some(store) => store.available.read().get(id).cloned(),
        None => None,
    }
}

pub fn is_installed(id: &[u8; 32]) -> bool {
    let lock = CAPSULE_STORE.lock();
    match lock.as_ref() {
        Some(store) => store.installed.read().contains_key(id),
        None => false,
    }
}

pub fn capsule_count() -> (usize, usize) {
    let lock = CAPSULE_STORE.lock();
    match lock.as_ref() {
        Some(store) => (
            store.installed.read().len(),
            store.available.read().len(),
        ),
        None => (0, 0),
    }
}
