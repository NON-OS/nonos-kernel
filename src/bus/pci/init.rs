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

use super::device::{device_exists, read_device};
use super::types::{DEVICES, DEVICE_COUNT, MAX_DEVICES, PCI_INIT};
use crate::sys::serial;
use core::sync::atomic::Ordering;

pub fn init() {
    if PCI_INIT.load(Ordering::Relaxed) {
        return;
    }
    serial::println(b"[PCI] Enumerating PCI devices...");
    let mut count: u32 = 0;
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            if device_exists(bus, device, 0) {
                let dev = read_device(bus, device, 0);
                if count < MAX_DEVICES as u32 {
                    unsafe {
                        DEVICES[count as usize] = dev;
                    }
                    count += 1;
                }
                if dev.header_type & 0x80 != 0 {
                    for function in 1..8u8 {
                        if device_exists(bus, device, function) {
                            let dev = read_device(bus, device, function);
                            if count < MAX_DEVICES as u32 {
                                unsafe {
                                    DEVICES[count as usize] = dev;
                                }
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    DEVICE_COUNT.store(count, Ordering::SeqCst);
    PCI_INIT.store(true, Ordering::SeqCst);
    serial::print(b"[PCI] Found ");
    serial::print_dec(count as u64);
    serial::println(b" devices");
    for i in 0..count as usize {
        let dev = unsafe { DEVICES[i] };
        if dev.is_valid() {
            log_device(&dev);
        }
    }
}

fn log_device(dev: &super::types::PciDevice) {
    let name = match (dev.class, dev.subclass, dev.prog_if) {
        (0x0C, 0x03, 0x30) => "xHCI USB 3.0",
        (0x0C, 0x03, 0x20) => "EHCI USB 2.0",
        (0x0C, 0x03, 0x10) => "OHCI USB 1.1",
        (0x0C, 0x03, 0x00) => "UHCI USB 1.0",
        (0x01, 0x06, _) => "SATA AHCI",
        (0x01, 0x08, _) => "NVMe",
        (0x02, 0x00, _) => "Ethernet",
        (0x03, 0x00, _) => "VGA Controller",
        (0x06, 0x00, _) => "Host Bridge",
        (0x06, 0x01, _) => "ISA Bridge",
        (0x06, 0x04, _) => "PCI-PCI Bridge",
        _ => "",
    };
    if !name.is_empty() {
        serial::print(b"[PCI] ");
        serial::print_dec(dev.bus as u64);
        serial::print(b":");
        serial::print_dec(dev.device as u64);
        serial::print(b".");
        serial::print_dec(dev.function as u64);
        serial::print(b" ");
        serial::print(name.as_bytes());
        serial::print(b" (");
        serial::print_hex(dev.vendor_id as u64);
        serial::print(b":");
        serial::print_hex(dev.device_id as u64);
        serial::println(b")");
    }
}
