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

use super::register_class;
use crate::fs::sysfs::kobject::{register_attribute, register_kobject, KobjectType};
use crate::fs::sysfs::types::SysfsAttribute;
use alloc::format;
use alloc::string::String;

static mut BLOCK_CLASS_INO: u64 = 0;

pub fn init_block_class() {
    unsafe {
        BLOCK_CLASS_INO = register_class("block");
    }
}

pub fn register_block_device(name: &str, dev_major: u32, dev_minor: u32, size_bytes: u64) -> u64 {
    let parent = unsafe { BLOCK_CLASS_INO };
    let ino = register_kobject(name, KobjectType::Device, parent);
    register_attribute(
        ino,
        SysfsAttribute::readonly("dev", move || format!("{}:{}\n", dev_major, dev_minor)),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("size", move || format!("{}\n", size_bytes / 512)),
    );
    register_attribute(ino, SysfsAttribute::readonly("stat", || read_block_stat()));
    register_attribute(ino, SysfsAttribute::readonly("ro", || String::from("0\n")));
    register_attribute(ino, SysfsAttribute::readonly("removable", || String::from("0\n")));
    ino
}

fn read_block_stat() -> String {
    let devices = crate::drivers::block::list_devices();
    if let Some(dev) = devices.first() {
        if let Some(stats) = crate::drivers::block::get_device_stats(&dev.name) {
            use core::sync::atomic::Ordering;
            return format!(
                "{:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}\n",
                stats.reads_completed.load(Ordering::Relaxed),
                stats.reads_merged.load(Ordering::Relaxed),
                stats.sectors_read.load(Ordering::Relaxed),
                stats.read_ms.load(Ordering::Relaxed),
                stats.writes_completed.load(Ordering::Relaxed),
                stats.writes_merged.load(Ordering::Relaxed),
                stats.sectors_written.load(Ordering::Relaxed),
                stats.write_ms.load(Ordering::Relaxed),
                stats.io_in_progress.load(Ordering::Relaxed),
                stats.io_ms.load(Ordering::Relaxed),
                stats.weighted_io_ms.load(Ordering::Relaxed)
            );
        }
    }
    format!(
        "{:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}\n",
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    )
}

pub fn get_block_devices() -> alloc::vec::Vec<String> {
    crate::drivers::block::list_devices().iter().map(|d| d.name.clone()).collect()
}

pub fn get_block_device_size(name: &str) -> Option<u64> {
    crate::drivers::block::get_device_info(name).map(|d| d.size_bytes)
}
