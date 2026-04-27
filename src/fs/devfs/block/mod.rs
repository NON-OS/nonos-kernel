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

mod loop_dev;
mod storage;

pub use loop_dev::{clear_loop, register_loop_device, setup_loop, LoopDevice};
pub use storage::{register_storage_device, StorageDevice};

use crate::fs::devfs::registry::register_device;
use crate::fs::devfs::types::DeviceType;

pub fn init_block_devices() {
    for i in 0..8 {
        loop_dev::register_loop_device(i);
    }
    for disk in crate::drivers::block::list_devices() {
        storage::register_storage_device(&disk.name, 8, 0, disk.size_bytes);
    }
}

pub fn create_block_device(name: &str, major: u32, minor: u32, mode: u32) -> Result<u64, i32> {
    register_device(name, DeviceType::BlockDevice, major, minor, mode)
}
