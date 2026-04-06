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
use alloc::format;
use super::register_class;
use crate::fs::sysfs::kobject::{register_kobject, KobjectType, register_attribute};
use crate::fs::sysfs::types::SysfsAttribute;

static mut BLOCK_CLASS_INO: u64 = 0;

pub fn init_block_class() {
    unsafe {
        BLOCK_CLASS_INO = register_class("block");
    }
}

pub fn register_block_device(name: &str, dev_major: u32, dev_minor: u32, size_bytes: u64) -> u64 {
    let parent = unsafe { BLOCK_CLASS_INO };
    let ino = register_kobject(name, KobjectType::Device, parent);
    register_attribute(ino, SysfsAttribute::readonly("dev", move || format!("{}:{}\n", dev_major, dev_minor)));
    register_attribute(ino, SysfsAttribute::readonly("size", move || format!("{}\n", size_bytes / 512)));
    register_attribute(ino, SysfsAttribute::readonly("stat", || read_block_stat()));
    register_attribute(ino, SysfsAttribute::readonly("ro", || String::from("0\n")));
    register_attribute(ino, SysfsAttribute::readonly("removable", || String::from("0\n")));
    ino
}

fn read_block_stat() -> String {
    format!("{:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}\n",
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
}

pub fn get_block_devices() -> alloc::vec::Vec<String> {
    crate::drivers::block::list_devices()
        .iter()
        .map(|d| d.name.clone())
        .collect()
}

pub fn get_block_device_size(name: &str) -> Option<u64> {
    crate::drivers::block::get_device(name).map(|d| d.size_bytes)
}
