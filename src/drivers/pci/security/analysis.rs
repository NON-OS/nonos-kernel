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

use super::super::constants::*;
use super::super::error::Result;
use super::super::types::PciDevice;
use super::approval::{approve_bus_master, check_device_allowed, is_bus_master_approved};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub fn is_dma_capable(device: &PciDevice) -> bool {
    match device.class() {
        CLASS_BRIDGE => false,
        CLASS_BASE_PERIPHERAL => device.subclass() != 0x05,
        _ => true,
    }
}

pub fn is_security_relevant(device: &PciDevice) -> bool {
    match (device.class(), device.subclass()) {
        (CLASS_SERIAL_BUS, SUBCLASS_SERIAL_USB) => true,
        (CLASS_NETWORK, _) => true,
        (CLASS_MASS_STORAGE, _) => true,
        (CLASS_DISPLAY, _) => true,
        (CLASS_WIRELESS, _) => true,
        _ => false,
    }
}

pub fn device_security_level(device: &PciDevice) -> SecurityLevel {
    if !is_dma_capable(device) {
        return SecurityLevel::Low;
    }

    match (device.class(), device.subclass()) {
        (CLASS_SERIAL_BUS, SUBCLASS_SERIAL_USB) => SecurityLevel::High,
        (CLASS_NETWORK, _) => SecurityLevel::High,
        (CLASS_MASS_STORAGE, SUBCLASS_STORAGE_NVM) => SecurityLevel::High,
        (CLASS_MASS_STORAGE, _) => SecurityLevel::Medium,
        (CLASS_DISPLAY, _) => SecurityLevel::Medium,
        (CLASS_WIRELESS, _) => SecurityLevel::Critical,
        (CLASS_ENCRYPTION, _) => SecurityLevel::Critical,
        _ => SecurityLevel::Low,
    }
}

pub struct DeviceAuditInfo {
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub dma_capable: bool,
    pub security_level: SecurityLevel,
    pub bus_master_approved: bool,
    pub msi_capable: bool,
    pub msix_capable: bool,
}

pub fn audit_device(device: &PciDevice) -> DeviceAuditInfo {
    DeviceAuditInfo {
        vendor_id: device.vendor_id(),
        device_id: device.device_id_value(),
        class: device.class(),
        subclass: device.subclass(),
        dma_capable: is_dma_capable(device),
        security_level: device_security_level(device),
        bus_master_approved: is_bus_master_approved(
            device.bus(),
            device.device(),
            device.function(),
        ),
        msi_capable: device.supports_msi(),
        msix_capable: device.supports_msix(),
    }
}

pub fn validate_device_for_driver(device: &PciDevice) -> Result<()> {
    check_device_allowed(device.vendor_id(), device.device_id_value())?;

    Ok(())
}

pub fn prepare_device_for_dma(device: &PciDevice) -> Result<()> {
    validate_device_for_driver(device)?;

    approve_bus_master(device.bus(), device.device(), device.function());

    Ok(())
}
