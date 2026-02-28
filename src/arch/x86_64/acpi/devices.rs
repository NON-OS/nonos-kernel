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
        // Assume 24 inputs per I/O APIC
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

#[derive(Debug, Clone)]
pub struct I2cHidDevice {
    pub hid: [u8; 8],
    pub cid: [u8; 8],
    pub uid: u32,
    pub i2c_address: u8,
    pub hid_desc_address: u16,
    pub interrupt_gpio: u32,
    pub device_type: I2cHidDeviceType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cHidDeviceType {
    Unknown,
    Touchpad,
    Touchscreen,
    Keyboard,
    Mouse,
    Stylus,
    Sensor,
}

const TOUCHPAD_HIDS: &[[u8; 8]] = &[
    *b"SYNA3602", *b"SYNA3609", *b"SYNA3619", *b"SYNA7813", *b"SYNA7817",
    *b"ELAN0001", *b"ELAN0100", *b"ELAN0600", *b"ELAN0601", *b"ELAN0602",
    *b"ELAN0603", *b"ELAN0617", *b"ELAN0618", *b"ELAN0619", *b"ELAN0620",
    *b"ELAN0621", *b"ELAN060B", *b"ELAN060C", *b"ELAN0611", *b"ELAN0612",
    *b"ELAN0650", *b"PNP0C50\0", *b"ACPI0C50", *b"MSFT0001",
    *b"ALPS0000", *b"ALPS0001", *b"CYAP0000", *b"CYAP0001", *b"FTSC1000",
];

const TOUCHSCREEN_HIDS: &[[u8; 8]] = &[
    *b"ELAN2514", *b"ELAN2097", *b"WCOM0000", *b"WCOM0001", *b"WCOM508C",
    *b"GXTP7380", *b"GXTP7386", *b"ATML1000", *b"ATML1001", *b"FTS3528\0",
];

impl I2cHidDevice {
    pub fn is_touchpad(&self) -> bool {
        self.device_type == I2cHidDeviceType::Touchpad
    }

    pub fn is_touchscreen(&self) -> bool {
        self.device_type == I2cHidDeviceType::Touchscreen
    }
}

pub fn enumerate_i2c_hid_devices() -> Vec<I2cHidDevice> {
    let mut devices = Vec::new();

    let known_touchpads = get_known_touchpad_configs();
    for tp in known_touchpads {
        devices.push(tp);
    }

    devices
}

pub fn find_touchpads() -> Vec<I2cHidDevice> {
    enumerate_i2c_hid_devices()
        .into_iter()
        .filter(|d| d.is_touchpad())
        .collect()
}

pub fn find_touchscreens() -> Vec<I2cHidDevice> {
    enumerate_i2c_hid_devices()
        .into_iter()
        .filter(|d| d.is_touchscreen())
        .collect()
}

fn get_known_touchpad_configs() -> Vec<I2cHidDevice> {
    let mut devices = Vec::new();

    devices.push(I2cHidDevice {
        hid: *b"SYNA3602",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x2C,
        hid_desc_address: 0x0020,
        interrupt_gpio: 10,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"ELAN0001",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x15,
        hid_desc_address: 0x0001,
        interrupt_gpio: 13,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"ELAN0617",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x15,
        hid_desc_address: 0x0001,
        interrupt_gpio: 14,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"SYNA7813",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x2C,
        hid_desc_address: 0x0020,
        interrupt_gpio: 15,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"ALPS0000",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x2C,
        hid_desc_address: 0x0020,
        interrupt_gpio: 9,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"CYAP0000",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x24,
        hid_desc_address: 0x0001,
        interrupt_gpio: 11,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"FTSC1000",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x38,
        hid_desc_address: 0x0001,
        interrupt_gpio: 12,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"MSFT0001",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x10,
        hid_desc_address: 0x0001,
        interrupt_gpio: 8,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices
}

pub fn classify_hid_device(hid: &[u8; 8]) -> I2cHidDeviceType {
    if TOUCHPAD_HIDS.contains(hid) {
        return I2cHidDeviceType::Touchpad;
    }
    if TOUCHSCREEN_HIDS.contains(hid) {
        return I2cHidDeviceType::Touchscreen;
    }

    let prefix = &hid[0..4];
    match prefix {
        b"SYNA" | b"ELAN" | b"ALPS" | b"CYAP" | b"FTSC" => I2cHidDeviceType::Touchpad,
        b"WCOM" | b"ATML" | b"GXTP" => I2cHidDeviceType::Touchscreen,
        _ => I2cHidDeviceType::Unknown,
    }
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
