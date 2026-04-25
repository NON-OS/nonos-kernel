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

use alloc::vec::Vec;
use spin::Mutex;

pub const MAX_APPS: usize = 64;
pub const MAX_KEYS: usize = 128;
pub const MAX_VALUE_SIZE: usize = 4096;

pub type StorageKey = [u8; 32];

#[derive(Clone)]
pub struct StorageEntry {
    pub key: StorageKey,
    pub value: Vec<u8>,
    pub app_id: u32,
}

static STORAGE: Mutex<Vec<StorageEntry>> = Mutex::new(Vec::new());

pub struct AppStorage {
    pub app_id: u32,
}

impl AppStorage {
    pub fn new(app_id: u32) -> Self {
        Self { app_id }
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut k = [0u8; 32];
        let len = key.len().min(32);
        k[..len].copy_from_slice(&key[..len]);
        let s = STORAGE.lock();
        s.iter().find(|e| e.app_id == self.app_id && e.key == k).map(|e| e.value.clone())
    }

    pub fn set(&self, key: &[u8], value: &[u8]) -> bool {
        if value.len() > MAX_VALUE_SIZE {
            return false;
        }
        let mut k = [0u8; 32];
        let len = key.len().min(32);
        k[..len].copy_from_slice(&key[..len]);
        let mut s = STORAGE.lock();
        if let Some(e) = s.iter_mut().find(|e| e.app_id == self.app_id && e.key == k) {
            e.value = value.to_vec();
            return true;
        }
        if s.len() < MAX_KEYS {
            s.push(StorageEntry { key: k, value: value.to_vec(), app_id: self.app_id });
            true
        } else {
            false
        }
    }

    pub fn delete(&self, key: &[u8]) -> bool {
        let mut k = [0u8; 32];
        let len = key.len().min(32);
        k[..len].copy_from_slice(&key[..len]);
        let mut s = STORAGE.lock();
        let before = s.len();
        s.retain(|e| !(e.app_id == self.app_id && e.key == k));
        s.len() < before
    }

    pub fn list_keys(&self) -> Vec<Vec<u8>> {
        let s = STORAGE.lock();
        s.iter()
            .filter(|e| e.app_id == self.app_id)
            .map(|e| e.key.iter().take_while(|&&b| b != 0).cloned().collect())
            .collect()
    }
}
