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
use super::device::{BlockDevice, BlockDeviceInfo};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub struct BlockIoStats {
    pub reads_completed: AtomicU64,
    pub reads_merged: AtomicU64,
    pub sectors_read: AtomicU64,
    pub read_ms: AtomicU64,
    pub writes_completed: AtomicU64,
    pub writes_merged: AtomicU64,
    pub sectors_written: AtomicU64,
    pub write_ms: AtomicU64,
    pub io_in_progress: AtomicU64,
    pub io_ms: AtomicU64,
    pub weighted_io_ms: AtomicU64,
}

impl BlockIoStats {
    pub const fn new() -> Self {
        Self {
            reads_completed: AtomicU64::new(0),
            reads_merged: AtomicU64::new(0),
            sectors_read: AtomicU64::new(0),
            read_ms: AtomicU64::new(0),
            writes_completed: AtomicU64::new(0),
            writes_merged: AtomicU64::new(0),
            sectors_written: AtomicU64::new(0),
            write_ms: AtomicU64::new(0),
            io_in_progress: AtomicU64::new(0),
            io_ms: AtomicU64::new(0),
            weighted_io_ms: AtomicU64::new(0),
        }
    }

    pub fn record_read(&self, sectors: u64) {
        self.reads_completed.fetch_add(1, Ordering::Relaxed);
        self.sectors_read.fetch_add(sectors, Ordering::Relaxed);
    }

    pub fn record_write(&self, sectors: u64) {
        self.writes_completed.fetch_add(1, Ordering::Relaxed);
        self.sectors_written.fetch_add(sectors, Ordering::Relaxed);
    }
}

impl Default for BlockIoStats {
    fn default() -> Self {
        Self::new()
    }
}

struct RegisteredDevice {
    name: String,
    device: Arc<dyn BlockDevice>,
    info: BlockDeviceInfo,
    stats: Arc<BlockIoStats>,
}

static DEVICES: Mutex<Vec<RegisteredDevice>> = Mutex::new(Vec::new());

pub fn register_device(name: &str, device: Arc<dyn BlockDevice>, info: BlockDeviceInfo) {
    let mut devs = DEVICES.lock();
    devs.push(RegisteredDevice {
        name: String::from(name),
        device,
        info,
        stats: Arc::new(BlockIoStats::new()),
    });
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

pub fn get_device_stats(name: &str) -> Option<Arc<BlockIoStats>> {
    DEVICES.lock().iter().find(|d| d.name == name).map(|d| d.stats.clone())
}

pub fn record_read(name: &str, bytes: usize) {
    if let Some(stats) = get_device_stats(name) {
        stats.record_read((bytes / 512) as u64);
    }
}

pub fn record_write(name: &str, bytes: usize) {
    if let Some(stats) = get_device_stats(name) {
        stats.record_write((bytes / 512) as u64);
    }
}
