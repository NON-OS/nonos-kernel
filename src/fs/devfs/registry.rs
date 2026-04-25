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

use super::types::{DeviceNode, DeviceOps, DeviceType};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

static NEXT_INO: AtomicU64 = AtomicU64::new(1000);
static DEVICES: Mutex<BTreeMap<u64, DeviceNode>> = Mutex::new(BTreeMap::new());
static DEVICE_OPS: Mutex<BTreeMap<u64, Arc<dyn DeviceOps>>> = Mutex::new(BTreeMap::new());

pub fn register_device(
    name: &str,
    dev_type: DeviceType,
    major: u32,
    minor: u32,
    mode: u32,
) -> Result<u64, i32> {
    let ino = NEXT_INO.fetch_add(1, Ordering::SeqCst);
    let node = match dev_type {
        DeviceType::CharDevice => DeviceNode::char_device(name, major, minor, mode, ino),
        DeviceType::BlockDevice => DeviceNode::block_device(name, major, minor, mode, ino),
    };
    DEVICES.lock().insert(ino, node);
    Ok(ino)
}

pub fn register_device_with_ops(
    name: &str,
    dev_type: DeviceType,
    major: u32,
    minor: u32,
    mode: u32,
    ops: Arc<dyn DeviceOps>,
) -> Result<u64, i32> {
    let ino = register_device(name, dev_type, major, minor, mode)?;
    DEVICE_OPS.lock().insert(ino, ops);
    Ok(ino)
}

pub fn unregister_device(inode: u64) {
    DEVICES.lock().remove(&inode);
    DEVICE_OPS.lock().remove(&inode);
}

pub fn get_device(name: &str) -> Option<DeviceNode> {
    DEVICES.lock().values().find(|d| d.name == name).cloned()
}

pub fn get_device_by_inode(inode: u64) -> Option<DeviceNode> {
    DEVICES.lock().get(&inode).cloned()
}

pub fn get_device_ops(inode: u64) -> Option<Arc<dyn DeviceOps>> {
    DEVICE_OPS.lock().get(&inode).cloned()
}

pub fn list_devices() -> Vec<DeviceNode> {
    DEVICES.lock().values().cloned().collect()
}

pub fn device_count() -> usize {
    DEVICES.lock().len()
}

pub fn find_device_by_dev(major: u32, minor: u32) -> Option<DeviceNode> {
    DEVICES.lock().values().find(|d| d.major == major && d.minor == minor).cloned()
}
