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

use core::ptr;
use alloc::vec::Vec;

use crate::arch::x86_64::acpi::parser;
use crate::arch::x86_64::acpi::data::PcieSegment;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDevice {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
}

impl PciDevice {
    pub fn bdf(&self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | (self.function as u16)
    }

    pub fn is_bridge(&self) -> bool {
        self.class == 0x06
    }

    pub fn is_storage(&self) -> bool {
        self.class == 0x01
    }

    pub fn is_network(&self) -> bool {
        self.class == 0x02
    }

    pub fn is_display(&self) -> bool {
        self.class == 0x03
    }
}

pub fn enumerate_pci_devices() -> Vec<PciDevice> {
    let mut devices = Vec::new();

    for seg in parser::pcie_segments() {
        for bus in seg.start_bus..=seg.end_bus {
            enumerate_bus(&seg, bus, &mut devices);
        }
    }

    devices
}

fn enumerate_bus(seg: &PcieSegment, bus: u8, devices: &mut Vec<PciDevice>) {
    for device in 0..32u8 {
        if let Some(dev) = probe_device(seg, bus, device, 0) {
            let is_multifunction = unsafe {
                if let Some(config_addr) = seg.config_address(bus, device, 0, 0x0E) {
                    let header_type = ptr::read_volatile(config_addr as *const u8);
                    header_type & 0x80 != 0
                } else {
                    false
                }
            };

            devices.push(dev);

            if is_multifunction {
                for function in 1..8u8 {
                    if let Some(dev) = probe_device(seg, bus, device, function) {
                        devices.push(dev);
                    }
                }
            }
        }
    }
}

fn probe_device(
    seg: &PcieSegment,
    bus: u8,
    device: u8,
    function: u8,
) -> Option<PciDevice> {
    let config_addr = seg.config_address(bus, device, function, 0)?;

    unsafe {
        let vendor_id = ptr::read_volatile(config_addr as *const u16);
        if vendor_id == 0xFFFF {
            return None;
        }

        let device_id = ptr::read_volatile((config_addr + 2) as *const u16);
        let class_code = ptr::read_volatile((config_addr + 9) as *const u8);
        let subclass = ptr::read_volatile((config_addr + 10) as *const u8);

        Some(PciDevice {
            segment: seg.segment,
            bus,
            device,
            function,
            vendor_id,
            device_id,
            class: class_code,
            subclass,
        })
    }
}

pub fn enumerate_pci_raw() -> Vec<(u16, u8, u8, u8)> {
    let mut devices = Vec::new();

    for seg in parser::pcie_segments() {
        for bus in seg.start_bus..=seg.end_bus {
            for device in 0..32u8 {
                for function in 0..8u8 {
                    if let Some(config_addr) = seg.config_address(bus, device, function, 0) {
                        unsafe {
                            let vendor_id = ptr::read_volatile(config_addr as *const u16);
                            if vendor_id != 0xFFFF {
                                devices.push((seg.segment, bus, device, function));

                                if function == 0 {
                                    let header_type = ptr::read_volatile(
                                        (config_addr + 0x0E) as *const u8
                                    );
                                    if header_type & 0x80 == 0 {
                                        break;
                                    }
                                }
                            } else if function == 0 {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    devices
}
