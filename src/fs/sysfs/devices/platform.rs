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

use super::register_root_device;
use crate::fs::sysfs::kobject::{register_attribute, register_kobject, KobjectType};
use crate::fs::sysfs::types::SysfsAttribute;
use alloc::format;
use alloc::string::String;

static mut PLATFORM_INO: u64 = 0;

pub fn init_platform_devices() {
    unsafe {
        PLATFORM_INO = register_root_device("platform");
    }
    register_platform_device("serial8250", "serial8250", 0);
    register_platform_device("pcspkr", "pcspkr", 0);
    register_platform_device("i8042", "i8042", 0);
}

pub fn register_platform_device(name: &str, driver: &str, id: u32) -> u64 {
    let dev_name = if id > 0 { format!("{}.{}", name, id) } else { String::from(name) };
    let parent = unsafe { PLATFORM_INO };
    let ino = register_kobject(&dev_name, KobjectType::Device, parent);
    let drv = String::from(driver);
    let name_owned = String::from(name);
    let driver_owned = String::from(driver);
    let name_owned2 = String::from(name);
    register_attribute(ino, SysfsAttribute::readonly("driver", move || format!("{}\n", drv)));
    register_attribute(
        ino,
        SysfsAttribute::readonly("modalias", move || format!("platform:{}\n", name_owned)),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("uevent", move || {
            format!("DRIVER={}\nMODALIAS=platform:{}\n", driver_owned, name_owned2)
        }),
    );
    ino
}

pub fn get_platform_devices() -> alloc::vec::Vec<String> {
    alloc::vec![String::from("serial8250"), String::from("pcspkr"), String::from("i8042"),]
}

pub fn get_platform_driver(name: &str) -> Option<String> {
    match name {
        "serial8250" => Some(String::from("serial8250")),
        "pcspkr" => Some(String::from("pcspkr")),
        "i8042" => Some(String::from("i8042")),
        _ => None,
    }
}
