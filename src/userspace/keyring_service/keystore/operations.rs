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

use super::storage::{clear_entry, Keyring};
use super::types::KeyMetadata;

impl Keyring {
    pub(super) fn lock(&mut self, id: u32, owner_pid: u32) -> bool {
        for entry in self.keys.iter_mut() {
            if entry.in_use && entry.metadata.id == id {
                if entry.metadata.owner_pid != owner_pid && owner_pid != 0 {
                    return false;
                }
                entry.metadata.locked = true;
                return true;
            }
        }
        false
    }

    pub(super) fn unlock(&mut self, id: u32, owner_pid: u32) -> bool {
        for entry in self.keys.iter_mut() {
            if entry.in_use && entry.metadata.id == id {
                if entry.metadata.owner_pid != owner_pid && owner_pid != 0 {
                    return false;
                }
                entry.metadata.locked = false;
                return true;
            }
        }
        false
    }

    pub(super) fn get_metadata(&self, id: u32) -> Option<KeyMetadata> {
        for entry in &self.keys {
            if entry.in_use && entry.metadata.id == id {
                return Some(entry.metadata);
            }
        }
        None
    }

    pub(super) fn count(&self) -> usize {
        self.keys.iter().filter(|e| e.in_use).count()
    }

    pub(super) fn cleanup_expired(&mut self) {
        let now = crate::sys::clock::uptime_seconds();
        for entry in self.keys.iter_mut() {
            if entry.in_use && entry.metadata.expires_at != 0 && now > entry.metadata.expires_at {
                clear_entry(entry);
            }
        }
    }
}
