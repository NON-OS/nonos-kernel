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

static mut INPUT_CLASS_INO: u64 = 0;

pub fn init_input_class() {
    unsafe {
        INPUT_CLASS_INO = register_class("input");
    }
}

pub fn register_input_device(
    name: &str,
    _input_type: InputType,
    bustype: u16,
    vendor: u16,
    product: u16,
) -> u64 {
    let parent = unsafe { INPUT_CLASS_INO };
    let ino = register_kobject(name, KobjectType::Device, parent);
    let name_owned = String::from(name);
    register_attribute(ino, SysfsAttribute::readonly("name", move || format!("{}\n", name_owned)));
    register_attribute(
        ino,
        SysfsAttribute::readonly("phys", || String::from("usb-0000:00:14.0-1/input0\n")),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("id/bustype", move || format!("{:04x}\n", bustype)),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("id/vendor", move || format!("{:04x}\n", vendor)),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("id/product", move || format!("{:04x}\n", product)),
    );
    register_attribute(ino, SysfsAttribute::readonly("id/version", || String::from("0110\n")));
    ino
}

#[derive(Debug, Clone, Copy)]
pub enum InputType {
    Keyboard,
    Mouse,
    Touchpad,
    Touchscreen,
    Joystick,
}

impl InputType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Keyboard => "keyboard",
            Self::Mouse => "mouse",
            Self::Touchpad => "touchpad",
            Self::Touchscreen => "touchscreen",
            Self::Joystick => "joystick",
        }
    }
}

pub fn get_input_devices() -> alloc::vec::Vec<String> {
    crate::input::list_devices().iter().map(|d| d.name.clone()).collect()
}
