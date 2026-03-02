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

use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::RwLock;

use super::traits::StorageDevice;

pub struct StorageManager {
    devices: RwLock<Vec<Arc<dyn StorageDevice>>>,
}

impl StorageManager {
    pub const fn new() -> Self {
        Self {
            devices: RwLock::new(Vec::new()),
        }
    }

    pub fn register_device(&self, device: Arc<dyn StorageDevice>) -> usize {
        let mut devices = self.devices.write();
        let idx = devices.len();
        devices.push(device);
        idx
    }

    pub fn device_count(&self) -> usize {
        self.devices.read().len()
    }

    pub fn get_device(&self, index: usize) -> Option<Arc<dyn StorageDevice>> {
        self.devices.read().get(index).cloned()
    }

    pub fn devices(&self) -> Vec<Arc<dyn StorageDevice>> {
        self.devices.read().clone()
    }
}

impl Default for StorageManager {
    fn default() -> Self {
        Self::new()
    }
}
