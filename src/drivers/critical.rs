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

use super::{get_ahci_controller, get_pci_manager};

#[derive(Debug, Clone)]
pub struct CriticalDriver {
    pub name: &'static str,
    pub driver_type: DriverType,
    pub base_address: usize,
    pub size: usize,
    pub hash: [u8; 32],
    pub version: u32,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone)]
pub enum DriverType {
    Storage,
    Network,
    Crypto,
    Security,
    System,
}

#[derive(Debug, Clone)]
pub enum SecurityLevel {
    Critical,
    High,
    Medium,
    Low,
}

pub fn get_critical_drivers() -> Vec<CriticalDriver> {
    let mut drivers = Vec::new();

    if let Some(ahci_ctrl) = get_ahci_controller() {
        drivers.push(CriticalDriver {
            name: "AHCI Storage Controller",
            driver_type: DriverType::Storage,
            base_address: ahci_ctrl as *const _ as usize,
            size: core::mem::size_of_val(ahci_ctrl),
            hash: crate::crypto::blake3::blake3_hash(unsafe {
                core::slice::from_raw_parts(
                    ahci_ctrl as *const _ as *const u8,
                    core::mem::size_of_val(ahci_ctrl),
                )
            }),
            version: 1,
            security_level: SecurityLevel::Critical,
        });
    }

    if let Some(nvme_ctrl) = super::nvme::get_controller() {
        drivers.push(CriticalDriver {
            name: "NVMe Storage Controller",
            driver_type: DriverType::Storage,
            base_address: nvme_ctrl as *const _ as usize,
            size: core::mem::size_of_val(nvme_ctrl),
            hash: crate::crypto::blake3::blake3_hash(unsafe {
                core::slice::from_raw_parts(
                    nvme_ctrl as *const _ as *const u8,
                    core::mem::size_of_val(nvme_ctrl),
                )
            }),
            version: 1,
            security_level: SecurityLevel::Critical,
        });
    }

    if let Some(pci_mgr) = get_pci_manager() {
        drivers.push(CriticalDriver {
            name: "PCI Bus Manager",
            driver_type: DriverType::System,
            base_address: pci_mgr as *const _ as usize,
            size: core::mem::size_of_val(pci_mgr),
            hash: crate::crypto::blake3::blake3_hash(unsafe {
                core::slice::from_raw_parts(
                    pci_mgr as *const _ as *const u8,
                    core::mem::size_of_val(pci_mgr),
                )
            }),
            version: 1,
            security_level: SecurityLevel::Critical,
        });
    }

    drivers
}
