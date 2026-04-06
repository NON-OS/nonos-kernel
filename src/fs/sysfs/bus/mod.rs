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

mod pci;
mod usb;

pub use pci::{init_pci_bus, register_pci_driver};
pub use usb::{init_usb_bus, register_usb_driver};

use super::kobject::{register_kobject, KobjectType};

static mut BUS_INO: u64 = 300;

pub fn init_bus_subsystem() {
    unsafe {
        BUS_INO = 300;
    }
    pci::init_pci_bus();
    usb::init_usb_bus();
}

pub fn get_bus_ino() -> u64 {
    unsafe { BUS_INO }
}

pub fn register_bus(name: &str) -> u64 {
    register_kobject(name, KobjectType::Bus, get_bus_ino())
}

pub fn get_bus_types() -> alloc::vec::Vec<&'static str> {
    alloc::vec!["pci", "usb", "platform", "acpi", "i2c", "spi"]
}
