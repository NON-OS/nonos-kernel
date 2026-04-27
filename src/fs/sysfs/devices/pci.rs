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

static mut PCI_ROOT_INO: u64 = 0;

pub fn init_pci_devices() {
    unsafe {
        PCI_ROOT_INO = register_root_device("pci0000:00");
    }
    for dev in crate::bus::pci::enumerate_devices() {
        register_pci_device(
            dev.bus,
            dev.device,
            dev.function,
            dev.vendor_id,
            dev.device_id,
            dev.class,
        );
    }
}

pub fn register_pci_device(
    bus: u8,
    device: u8,
    func: u8,
    vendor: u16,
    dev_id: u16,
    class: u32,
) -> u64 {
    let name = format!("0000:{:02x}:{:02x}.{}", bus, device, func);
    let parent = unsafe { PCI_ROOT_INO };
    let ino = register_kobject(&name, KobjectType::Device, parent);
    register_attribute(
        ino,
        SysfsAttribute::readonly("vendor", move || format!("0x{:04x}\n", vendor)),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("device", move || format!("0x{:04x}\n", dev_id)),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("class", move || format!("0x{:06x}\n", class)),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("subsystem_vendor", || String::from("0x0000\n")),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("subsystem_device", || String::from("0x0000\n")),
    );
    register_attribute(ino, SysfsAttribute::readonly("enable", || String::from("1\n")));
    register_attribute(ino, SysfsAttribute::readonly("irq", || String::from("0\n")));
    register_attribute(ino, SysfsAttribute::readonly("numa_node", || String::from("-1\n")));
    ino
}

pub fn get_pci_devices() -> alloc::vec::Vec<PciDeviceInfo> {
    crate::bus::pci::enumerate_devices()
        .iter()
        .map(|d| PciDeviceInfo {
            bdf: format!("0000:{:02x}:{:02x}.{}", d.bus, d.device, d.function),
            vendor_id: d.vendor_id,
            device_id: d.device_id,
        })
        .collect()
}

pub struct PciDeviceInfo {
    pub bdf: String,
    pub vendor_id: u16,
    pub device_id: u16,
}
