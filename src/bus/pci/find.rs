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

use core::sync::atomic::Ordering;
use super::types::{PciDevice, PCI_INIT, DEVICE_COUNT, DEVICES};

pub fn find_device_by_id(vendor: u16, device_id: u16) -> Option<PciDevice> {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    for i in 0..count {
        let dev = unsafe { DEVICES[i] };
        if dev.vendor_id == vendor && dev.device_id == device_id { return Some(dev); }
    }
    None
}

pub fn find_device(class: u8, subclass: u8, prog_if: Option<u8>) -> Option<PciDevice> {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    for i in 0..count {
        let dev = unsafe { DEVICES[i] };
        if dev.class == class && dev.subclass == subclass {
            if let Some(pi) = prog_if { if dev.prog_if == pi { return Some(dev); } }
            else { return Some(dev); }
        }
    }
    None
}

pub fn find_devices(class: u8, subclass: u8) -> impl Iterator<Item = PciDevice> {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    (0..count).filter_map(move |i| {
        let dev = unsafe { DEVICES[i] };
        if dev.class == class && dev.subclass == subclass { Some(dev) } else { None }
    })
}

pub fn get_device(index: usize) -> Option<PciDevice> {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    if index < count { Some(unsafe { DEVICES[index] }) } else { None }
}

pub fn device_count() -> usize { DEVICE_COUNT.load(Ordering::Relaxed) as usize }

pub fn is_init() -> bool { PCI_INIT.load(Ordering::Relaxed) }

pub fn enumerate_devices() -> alloc::vec::Vec<PciDeviceExt> {
    extern crate alloc;
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    (0..count).filter_map(|i| {
        let dev = unsafe { DEVICES[i] };
        if dev.is_valid() {
            Some(PciDeviceExt {
                bus: dev.bus, device: dev.device, function: dev.function,
                vendor_id: dev.vendor_id, device_id: dev.device_id,
                class: ((dev.class as u32) << 16) | ((dev.subclass as u32) << 8) | (dev.prog_if as u32),
            })
        } else { None }
    }).collect()
}

pub struct PciDeviceExt { pub bus: u8, pub device: u8, pub function: u8, pub vendor_id: u16, pub device_id: u16, pub class: u32 }

pub fn rescan() { crate::bus::pci::init::init(); }

pub fn bind_driver(_bdf: &str) -> Result<(), i32> { Ok(()) }

pub fn unbind_driver(_bdf: &str) -> Result<(), i32> { Ok(()) }

pub struct PciDriver { pub name: alloc::string::String }

pub fn list_drivers() -> alloc::vec::Vec<PciDriver> {
    extern crate alloc;
    alloc::vec![PciDriver { name: alloc::string::String::from("pci-generic") }]
}

pub fn get_driver_devices(_driver: &str) -> alloc::vec::Vec<alloc::string::String> {
    extern crate alloc;
    enumerate_devices().iter().map(|d| alloc::format!("0000:{:02x}:{:02x}.{}", d.bus, d.device, d.function)).collect()
}
