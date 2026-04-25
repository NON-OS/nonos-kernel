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

use crate::firmware::types::FirmwareType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType { WiFi, Ethernet, Gpu, Audio, Storage, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult { Detected, NotFound, Error, Incompatible }

#[derive(Debug, Clone)]
pub struct HardwareDevice { pub device_type: DeviceType, pub vendor_id: u16, pub device_id: u16, pub subsystem_id: u16, pub revision: u8, pub firmware_type: FirmwareType }

pub fn detect_hardware_devices() -> alloc::vec::Vec<HardwareDevice> {
    let mut devices = alloc::vec::Vec::new();
    for bus in 0..8 { for device in 0..32 { for function in 0..8 { if let Some(hw_device) = probe_pci_device(bus, device, function) { devices.push(hw_device); } } } }
    devices
}

pub fn probe_device(vendor_id: u16, device_id: u16) -> ProbeResult {
    if vendor_id == 0xFFFF || device_id == 0xFFFF { return ProbeResult::NotFound; }
    let device_type = classify_device(vendor_id, device_id);
    if device_type == DeviceType::Unknown { return ProbeResult::Incompatible; }
    if is_supported_device(vendor_id, device_id) { ProbeResult::Detected } else { ProbeResult::Incompatible }
}

fn probe_pci_device(bus: u8, device: u8, function: u8) -> Option<HardwareDevice> {
    let config_addr = 0x80000000 | (u32::from(bus) << 16) | (u32::from(device) << 11) | (u32::from(function) << 8);
    let vendor_device = read_pci_config(config_addr);
    if (vendor_device & 0xFFFF) == 0xFFFF { return None; }
    let vendor_id = (vendor_device & 0xFFFF) as u16;
    let device_id = (vendor_device >> 16) as u16;
    let class_revision = read_pci_config(config_addr + 8);
    let revision = (class_revision & 0xFF) as u8;
    let subsystem = read_pci_config(config_addr + 44);
    let subsystem_id = (subsystem >> 16) as u16;
    let device_type = classify_device(vendor_id, device_id);
    let firmware_type = map_to_firmware_type(vendor_id, device_id);
    Some(HardwareDevice { device_type, vendor_id, device_id, subsystem_id, revision, firmware_type })
}

fn classify_device(vendor_id: u16, device_id: u16) -> DeviceType {
    match vendor_id { 0x8086 => match device_id { 0x24FD..=0x24FF => DeviceType::WiFi, 0x15B7..=0x15B9 => DeviceType::Ethernet, 0x1912..=0x1932 => DeviceType::Gpu, _ => DeviceType::Unknown }, 0x10EC => DeviceType::WiFi, 0x1002 => DeviceType::Gpu, 0x10DE => DeviceType::Gpu, _ => DeviceType::Unknown }
}

fn map_to_firmware_type(vendor_id: u16, device_id: u16) -> FirmwareType {
    match (vendor_id, device_id) { (0x8086, 0x24FD) => FirmwareType::IntelAx200, (0x8086, 0x24F3) => FirmwareType::IntelAx210, (0x8086, 0x24F4) => FirmwareType::Intel8265, (0x10EC, 0xC821) => FirmwareType::Rtl8821c, (0x10EC, 0xC822) => FirmwareType::Rtl8822c, _ => FirmwareType::Unknown }
}

fn is_supported_device(vendor_id: u16, device_id: u16) -> bool { map_to_firmware_type(vendor_id, device_id) != FirmwareType::Unknown }
fn read_pci_config(addr: u32) -> u32 { addr.wrapping_add(0x12345678) }