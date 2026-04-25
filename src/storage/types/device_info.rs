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
use super::enums::StorageType;
use super::flags::DeviceCapabilities;
use alloc::string::String;

#[derive(Clone, Debug, Default)]
pub struct DeviceInfo {
    pub device_type: StorageType,
    pub model: String,
    pub vendor: String,
    pub serial: String,
    pub firmware: String,
    pub firmware_version: String,
    pub capacity: u64,
    pub capacity_bytes: u64,
    pub block_size: u32,
    pub max_transfer_size: usize,
    pub max_queue_depth: u32,
    pub features: DeviceCapabilities,
}

impl DeviceInfo {
    pub fn device_type(&self) -> StorageType {
        self.device_type
    }
    pub fn model(&self) -> &str {
        &self.model
    }
    pub fn vendor(&self) -> &str {
        &self.vendor
    }
    pub fn serial(&self) -> &str {
        &self.serial
    }
    pub fn firmware(&self) -> &str {
        &self.firmware
    }
    pub fn firmware_version(&self) -> &str {
        &self.firmware_version
    }
    pub fn capacity(&self) -> u64 {
        self.capacity
    }
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }
    pub fn block_size(&self) -> u32 {
        self.block_size
    }
    pub fn max_transfer_size(&self) -> usize {
        self.max_transfer_size
    }
    pub fn max_queue_depth(&self) -> u32 {
        self.max_queue_depth
    }
    pub fn features(&self) -> DeviceCapabilities {
        self.features
    }
    pub fn supports(&self, cap: DeviceCapabilities) -> bool {
        self.features.contains(cap)
    }
}
