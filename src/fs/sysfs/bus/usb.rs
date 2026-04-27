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

use super::register_bus;
use crate::fs::sysfs::kobject::{register_attribute, register_kobject, KobjectType};
use crate::fs::sysfs::types::SysfsAttribute;
use alloc::format;
use alloc::string::String;

static mut USB_BUS_INO: u64 = 0;
static mut USB_DRIVERS_INO: u64 = 0;
static mut USB_DEVICES_INO: u64 = 0;

pub fn init_usb_bus() {
    unsafe {
        USB_BUS_INO = register_bus("usb");
        USB_DRIVERS_INO = register_kobject("drivers", KobjectType::Subsystem, USB_BUS_INO);
        USB_DEVICES_INO = register_kobject("devices", KobjectType::Subsystem, USB_BUS_INO);
    }
    register_attribute(
        unsafe { USB_BUS_INO },
        SysfsAttribute::readonly("uevent", || String::new()),
    );
}

pub fn register_usb_driver(name: &str) -> u64 {
    let parent = unsafe { USB_DRIVERS_INO };
    let ino = register_kobject(name, KobjectType::Driver, parent);
    let name_owned = String::from(name);
    register_attribute(
        ino,
        SysfsAttribute::readonly("module", move || format!("{}\n", name_owned)),
    );
    register_attribute(
        ino,
        SysfsAttribute::writeonly("bind", |dev| {
            crate::drivers::usb::bind_driver(dev)?;
            Ok(())
        }),
    );
    register_attribute(
        ino,
        SysfsAttribute::writeonly("unbind", |dev| {
            crate::drivers::usb::unbind_driver(dev)?;
            Ok(())
        }),
    );
    ino
}

pub fn register_usb_device(path: &str, vendor: u16, product: u16, class: u8) -> u64 {
    let parent = unsafe { USB_DEVICES_INO };
    let ino = register_kobject(path, KobjectType::Device, parent);
    register_attribute(
        ino,
        SysfsAttribute::readonly("idVendor", move || format!("{:04x}\n", vendor)),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("idProduct", move || format!("{:04x}\n", product)),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("bDeviceClass", move || format!("{:02x}\n", class)),
    );
    register_attribute(ino, SysfsAttribute::readonly("speed", || String::from("480\n")));
    ino
}

pub fn get_usb_devices() -> alloc::vec::Vec<String> {
    crate::drivers::usb::list_devices().iter().map(|d| d.path.clone()).collect()
}
