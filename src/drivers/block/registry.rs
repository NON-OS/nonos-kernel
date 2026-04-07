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
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;
use super::device::{BlockDevice, BlockDeviceInfo};

struct RegisteredDevice {
    name: String,
    device: Arc<dyn BlockDevice>,
    info: BlockDeviceInfo,
}

static DEVICES: Mutex<Vec<RegisteredDevice>> = Mutex::new(Vec::new());

pub fn register_device(name: &str, device: Arc<dyn BlockDevice>, info: BlockDeviceInfo) {
    let mut devs = DEVICES.lock();
    devs.push(RegisteredDevice { name: String::from(name), device, info });
}

pub fn unregister_device(name: &str) {
    let mut devs = DEVICES.lock();
    devs.retain(|d| d.name != name);
}

pub fn list_disks() -> Vec<String> {
    DEVICES.lock().iter().map(|d| d.name.clone()).collect()
}

pub fn get_device(name: &str) -> Option<Arc<dyn BlockDevice>> {
    DEVICES.lock().iter().find(|d| d.name == name).map(|d| d.device.clone())
}

pub fn get_device_info(name: &str) -> Option<BlockDeviceInfo> {
    DEVICES.lock().iter().find(|d| d.name == name).map(|d| d.info.clone())
}

pub fn list_devices() -> Vec<BlockDeviceInfo> {
    DEVICES.lock().iter().map(|d| d.info.clone()).collect()
}
