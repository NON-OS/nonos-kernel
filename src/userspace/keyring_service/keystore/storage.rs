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

use super::types::{KeyEntry, KeyMetadata, KeyType, MAX_KEYS, MAX_KEY_SIZE};
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub(super) struct Keyring {
    pub keys: [KeyEntry; MAX_KEYS],
}

impl Keyring {
    pub(super) const fn new() -> Self {
        const EMPTY: KeyEntry = KeyEntry::empty();
        Self { keys: [EMPTY; MAX_KEYS] }
    }

    pub(super) fn store(
        &mut self,
        key_type: KeyType,
        data: &[u8],
        owner_pid: u32,
        expires_at: u64,
    ) -> Option<u32> {
        if data.len() > MAX_KEY_SIZE {
            return None;
        }
        for entry in self.keys.iter_mut() {
            if !entry.in_use {
                let id = NEXT_KEY_ID.fetch_add(1, Ordering::Relaxed);
                entry.metadata = KeyMetadata {
                    id,
                    key_type,
                    size: data.len(),
                    owner_pid,
                    created_at: crate::sys::clock::uptime_seconds(),
                    expires_at,
                    use_count: 0,
                    locked: false,
                };
                entry.data[..data.len()].copy_from_slice(data);
                entry.in_use = true;
                return Some(id);
            }
        }
        None
    }

    pub(super) fn retrieve(
        &mut self,
        id: u32,
        owner_pid: u32,
    ) -> Option<([u8; MAX_KEY_SIZE], usize)> {
        for entry in self.keys.iter_mut() {
            if entry.in_use && entry.metadata.id == id {
                if entry.metadata.owner_pid != owner_pid && owner_pid != 0 {
                    return None;
                }
                if entry.metadata.expires_at != 0
                    && crate::sys::clock::uptime_seconds() > entry.metadata.expires_at
                {
                    clear_entry(entry);
                    return None;
                }
                if entry.metadata.locked {
                    return None;
                }
                entry.metadata.use_count += 1;
                return Some((entry.data, entry.metadata.size));
            }
        }
        None
    }

    pub(super) fn delete(&mut self, id: u32, owner_pid: u32) -> bool {
        for entry in self.keys.iter_mut() {
            if entry.in_use && entry.metadata.id == id {
                if entry.metadata.owner_pid != owner_pid && owner_pid != 0 {
                    return false;
                }
                clear_entry(entry);
                return true;
            }
        }
        false
    }
}

pub(super) fn clear_entry(entry: &mut KeyEntry) {
    entry.data = [0u8; MAX_KEY_SIZE];
    entry.metadata = KeyMetadata {
        id: 0,
        key_type: KeyType::Symmetric,
        size: 0,
        owner_pid: 0,
        created_at: 0,
        expires_at: 0,
        use_count: 0,
        locked: false,
    };
    entry.in_use = false;
}

pub(super) static KEYRING: Mutex<Keyring> = Mutex::new(Keyring::new());
pub(super) static NEXT_KEY_ID: AtomicU32 = AtomicU32::new(1);
