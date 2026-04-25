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

static mut PCI_BUS_INO: u64 = 0;
static mut PCI_DRIVERS_INO: u64 = 0;
static mut PCI_DEVICES_INO: u64 = 0;

pub fn init_pci_bus() {
    unsafe {
        PCI_BUS_INO = register_bus("pci");
        PCI_DRIVERS_INO = register_kobject("drivers", KobjectType::Subsystem, PCI_BUS_INO);
        PCI_DEVICES_INO = register_kobject("devices", KobjectType::Subsystem, PCI_BUS_INO);
    }
    register_attribute(
        unsafe { PCI_BUS_INO },
        SysfsAttribute::readonly("uevent", || String::new()),
    );
    register_attribute(
        unsafe { PCI_BUS_INO },
        SysfsAttribute::writeonly("rescan", |_| {
            crate::bus::pci::rescan();
            Ok(())
        }),
    );
}

pub fn register_pci_driver(name: &str) -> u64 {
    let parent = unsafe { PCI_DRIVERS_INO };
    let ino = register_kobject(name, KobjectType::Driver, parent);
    let name_owned = String::from(name);
    register_attribute(
        ino,
        SysfsAttribute::readonly("module", move || format!("{}\n", name_owned)),
    );
    register_attribute(
        ino,
        SysfsAttribute::writeonly("bind", |bdf| {
            crate::bus::pci::bind_driver(bdf)?;
            Ok(())
        }),
    );
    register_attribute(
        ino,
        SysfsAttribute::writeonly("unbind", |bdf| {
            crate::bus::pci::unbind_driver(bdf)?;
            Ok(())
        }),
    );
    ino
}

pub fn get_pci_drivers() -> alloc::vec::Vec<String> {
    crate::bus::pci::list_drivers().iter().map(|d| d.name.clone()).collect()
}

pub fn get_driver_devices(driver: &str) -> alloc::vec::Vec<String> {
    crate::bus::pci::get_driver_devices(driver)
}
