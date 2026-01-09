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

use alloc::vec::Vec;

use super::critical::DriverType;
use super::pci;

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: &'static str,
    pub device_type: DriverType,
    pub vendor_id: u16,
    pub device_id: u16,
    pub address: usize,
    pub size: usize,
    pub capabilities: u32,
    pub security_status: SecurityStatus,
}

#[derive(Debug, Clone)]
pub enum SecurityStatus {
    Verified,
    Unverified,
    Suspicious,
    Blocked,
}

pub fn get_all_devices() -> Vec<DeviceInfo> {
    let mut devices = Vec::new();
    let pci_devices = pci::scan_and_collect();
    for pci_dev in pci_devices {
        let bar_addr = match &pci_dev.bars[0] {
            pci::PciBar::Memory32 { address, .. } => address.as_u64() as usize,
            pci::PciBar::Memory64 { address, .. } => address.as_u64() as usize,
            pci::PciBar::Memory { address, .. } => address.as_u64() as usize,
            pci::PciBar::Io { port, .. } => *port as usize,
            pci::PciBar::NotPresent => 0,
        };
        let bar_size = pci_dev.bars[0].size() as usize;
        devices.push(DeviceInfo {
            name: match (pci_dev.vendor_id(), pci_dev.device_id_value()) {
                (0x8086, _) => "Intel Device",
                (0x1022, _) => "AMD Device",
                (0x10DE, _) => "NVIDIA Device",
                (0x1234, 0x1111) => "QEMU VGA",
                (0x1AF4, _) => "VirtIO Device",
                _ => "Unknown Device",
            },
            device_type: classify_device_type(pci_dev.class() as u32),
            vendor_id: pci_dev.vendor_id(),
            device_id: pci_dev.device_id_value(),
            address: bar_addr,
            size: bar_size,
            capabilities: pci_dev.capabilities.iter().fold(0u32, |acc, cap| {
                acc | match cap.id {
                    0x01 => 0x01,
                    0x05 => 0x02,
                    0x10 => 0x04,
                    0x11 => 0x08,
                    _ => 0x00,
                }
            }),
            security_status: SecurityStatus::Verified,
        });
    }

    devices.push(DeviceInfo {
        name: "System Timer",
        device_type: DriverType::System,
        vendor_id: 0,
        device_id: 0,
        address: 0,
        size: 0,
        capabilities: 0,
        security_status: SecurityStatus::Verified,
    });

    devices.push(DeviceInfo {
        name: "Interrupt Controller",
        device_type: DriverType::System,
        vendor_id: 0,
        device_id: 0,
        address: 0,
        size: 0,
        capabilities: 0,
        security_status: SecurityStatus::Verified,
    });

    devices
}

fn classify_device_type(class_code: u32) -> DriverType {
    match (class_code >> 16) & 0xFF {
        0x01 => DriverType::Storage,
        0x02 => DriverType::Network,
        0x03 => DriverType::System,
        0x04 => DriverType::System,
        0x0C => match (class_code >> 8) & 0xFF {
            0x03 => DriverType::System,
            _ => DriverType::System,
        },
        0x10 => DriverType::Crypto,
        _ => DriverType::System,
    }
}
