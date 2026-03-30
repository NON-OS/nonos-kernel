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
