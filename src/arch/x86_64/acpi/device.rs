// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::parser;

pub fn get_hpet_base() -> Option<u64> {
    parser::hpet_address()
}

pub fn get_lapic_base() -> Option<u64> {
    parser::lapic_address()
}

pub fn get_pcie_ecam(segment: u16, bus: u8) -> Option<u64> {
    for seg in parser::pcie_segments() {
        if seg.segment == segment && bus >= seg.start_bus && bus <= seg.end_bus {
            return Some(seg.base_address);
        }
    }
    None
}

pub fn get_ioapic_addresses() -> Vec<u64> {
    parser::ioapics().iter().map(|io| io.address).collect()
}

pub fn get_ioapic_for_gsi(gsi: u32) -> Option<u64> {
    for io in parser::ioapics() {
        if gsi >= io.gsi_base && gsi < io.gsi_base + 24 {
            return Some(io.address);
        }
    }
    None
}

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

fn enumerate_bus(seg: &super::data::PcieSegment, bus: u8, devices: &mut Vec<PciDevice>) {
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
    seg: &super::data::PcieSegment,
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

                                // Check if multi-function
                                if function == 0 {
                                    let header_type = ptr::read_volatile(
                                        (config_addr + 0x0E) as *const u8
                                    );
                                    if header_type & 0x80 == 0 {
                                        break; // Not multi-function
                                    }
                                }
                            } else if function == 0 {
                                break; // No device at function 0
                            }
                        }
                    }
                }
            }
        }
    }

    devices
}

pub fn irq_to_gsi(irq: u8) -> u32 {
    for ovr in parser::interrupt_overrides() {
        if ovr.source_irq == irq {
            return ovr.gsi;
        }
    }
    irq as u32
}

pub fn is_irq_level_triggered(irq: u8) -> bool {
    for ovr in parser::interrupt_overrides() {
        if ovr.source_irq == irq {
            return ovr.is_level_triggered();
        }
    }
    false // ISA IRQs are edge-triggered by default
}

pub fn is_irq_active_low(irq: u8) -> bool {
    for ovr in parser::interrupt_overrides() {
        if ovr.source_irq == irq {
            return ovr.is_active_low();
        }
    }
    false // ISA IRQs are active-high by default
}

pub fn processor_count() -> usize {
    parser::processors().len()
}

pub fn enabled_processor_count() -> usize {
    parser::processors().iter().filter(|p| p.enabled).count()
}

pub fn has_legacy_pics() -> bool {
    parser::has_legacy_pics().unwrap_or(true)
}

pub fn numa_domains() -> Vec<u32> {
    let mut domains = Vec::new();
    for region in parser::numa_regions() {
        if !domains.contains(&region.proximity_domain) {
            domains.push(region.proximity_domain);
        }
    }
    domains.sort();
    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pci_device_bdf() {
        let dev = PciDevice {
            segment: 0,
            bus: 1,
            device: 2,
            function: 3,
            vendor_id: 0,
            device_id: 0,
            class: 0,
            subclass: 0,
        };
        // BDF = (1 << 8) | (2 << 3) | 3 = 256 + 16 + 3 = 275
        assert_eq!(dev.bdf(), 275);
    }

    #[test]
    fn test_pci_device_class_checks() {
        let bridge = PciDevice {
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
            vendor_id: 0,
            device_id: 0,
            class: 0x06,
            subclass: 0,
        };
        assert!(bridge.is_bridge());
        assert!(!bridge.is_storage());

        let storage = PciDevice {
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
            vendor_id: 0,
            device_id: 0,
            class: 0x01,
            subclass: 0,
        };
        assert!(storage.is_storage());
        assert!(!storage.is_network());
    }
}
