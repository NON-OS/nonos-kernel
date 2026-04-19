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

static mut TTY_CLASS_INO: u64 = 0;

pub fn init_tty_class() {
    unsafe {
        TTY_CLASS_INO = register_class("tty");
    }
    register_tty_device("tty0", 4, 0);
    register_tty_device("tty1", 4, 1);
    register_tty_device("console", 5, 1);
    register_tty_device("ttyS0", 4, 64);
}

pub fn register_tty_device(name: &str, major: u32, minor: u32) -> u64 {
    let parent = unsafe { TTY_CLASS_INO };
    let ino = register_kobject(name, KobjectType::Device, parent);
    register_attribute(ino, SysfsAttribute::readonly("dev", move || format!("{}:{}\n", major, minor)));
    register_attribute(ino, SysfsAttribute::readonly("type", || String::from("tty\n")));
    ino
}

pub fn get_tty_devices() -> alloc::vec::Vec<String> {
    alloc::vec![
        String::from("tty0"),
        String::from("tty1"),
        String::from("console"),
        String::from("ttyS0"),
    ]
}

pub fn get_active_tty() -> Option<String> {
    if let Some(vt) = crate::tty::console::get_active_vt() {
        Some(format!("tty{}", vt.num + 1))
    } else {
        Some(String::from("tty1"))
    }
}

pub fn get_tty_driver(name: &str) -> Option<String> {
    if name.starts_with("ttyS") {
        Some(String::from("serial"))
    } else if name.starts_with("tty") || name == "console" {
        Some(String::from("vt"))
    } else {
        None
    }
}
