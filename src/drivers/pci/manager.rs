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

extern crate alloc;

use alloc::vec::Vec;
use spin::{Mutex, Once};

use super::bar::decode_all_bars_unchecked;
use super::capabilities::{
    collect_all_capabilities, enumerate_pcie_capabilities, get_msi_info, get_msix_info,
    get_pcie_info, get_power_management_info,
};
use super::config::{read32_unchecked, ConfigSpace};
use super::constants::*;
use super::error::{PciError, Result};
use super::security::{check_device_allowed, is_dma_capable};
use super::stats::{self, PciStats};
use super::types::{ClassCode, DeviceId, HeaderType, PciAddress, PciDevice};

static PCI_MANAGER: Once<Mutex<PciManager>> = Once::new();

pub struct PciManager {
    devices: Vec<PciDevice>,
    initialized: bool,
}

impl PciManager {
    fn new() -> Self {
        Self {
            devices: Vec::new(),
            initialized: false,
        }
    }

    pub fn devices(&self) -> &[PciDevice] {
        &self.devices
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn find_by_class(&self, class: u8, subclass: u8) -> Option<&PciDevice> {
        self.devices
            .iter()
            .find(|d| d.class() == class && d.subclass() == subclass)
    }

    pub fn find_by_class_progif(&self, class: u8, subclass: u8, progif: u8) -> Option<&PciDevice> {
        self.devices.iter().find(|d| {
            d.class() == class && d.subclass() == subclass && d.prog_if() == progif
        })
    }

    pub fn find_by_vendor_device(&self, vendor: u16, device: u16) -> Option<&PciDevice> {
        self.devices
            .iter()
            .find(|d| d.vendor_id() == vendor && d.device_id_value() == device)
    }

    pub fn find_by_address(&self, bus: u8, device: u8, function: u8) -> Option<&PciDevice> {
        self.devices.iter().find(|d| {
            d.bus() == bus && d.device() == device && d.function() == function
        })
    }

    pub fn find_all_by_class(&self, class: u8) -> Vec<&PciDevice> {
        self.devices.iter().filter(|d| d.class() == class).collect()
    }

    pub fn find_all_by_vendor(&self, vendor: u16) -> Vec<&PciDevice> {
        self.devices
            .iter()
            .filter(|d| d.vendor_id() == vendor)
            .collect()
    }

    pub fn find_usb_controllers(&self) -> Vec<&PciDevice> {
        self.devices.iter().filter(|d| d.is_usb_controller()).collect()
    }

    pub fn find_nvme_controllers(&self) -> Vec<&PciDevice> {
        self.devices.iter().filter(|d| d.is_nvme_controller()).collect()
    }

    pub fn find_ahci_controllers(&self) -> Vec<&PciDevice> {
        self.devices.iter().filter(|d| d.is_ahci_controller()).collect()
    }

    pub fn find_network_controllers(&self) -> Vec<&PciDevice> {
        self.devices
            .iter()
            .filter(|d| d.is_network_controller())
            .collect()
    }

    pub fn find_display_controllers(&self) -> Vec<&PciDevice> {
        self.devices
            .iter()
            .filter(|d| d.is_display_controller())
            .collect()
    }

    pub fn find_bridges(&self) -> Vec<&PciDevice> {
        self.devices.iter().filter(|d| d.is_bridge()).collect()
    }

    pub fn find_pcie_devices(&self) -> Vec<&PciDevice> {
        self.devices.iter().filter(|d| d.is_pcie()).collect()
    }

    pub fn find_msi_capable(&self) -> Vec<&PciDevice> {
        self.devices.iter().filter(|d| d.supports_msi()).collect()
    }

    pub fn find_msix_capable(&self) -> Vec<&PciDevice> {
        self.devices.iter().filter(|d| d.supports_msix()).collect()
    }

    pub fn get_stats(&self) -> PciStats {
        let mut stats = PciStats::snapshot();
        stats.total_devices = self.devices.len() as u64;

        for device in &self.devices {
            *stats.devices_by_class.entry(device.class()).or_insert(0) += 1;
            *stats.devices_by_vendor.entry(device.vendor_id()).or_insert(0) += 1;
        }

        stats
    }
}

fn probe_device(bus: u8, device_num: u8, function: u8) -> Option<PciDevice> {
    let id = read32_unchecked(bus, device_num, function, CFG_VENDOR_ID as u8);
    let vendor_id = (id & 0xFFFF) as u16;

    if vendor_id == 0xFFFF || vendor_id == 0x0000 {
        return None;
    }

    let device_id = ((id >> 16) & 0xFFFF) as u16;

    if check_device_allowed(vendor_id, device_id).is_err() {
        return None;
    }

    let class_reg = read32_unchecked(bus, device_num, function, CFG_REVISION_ID as u8);
    let revision = (class_reg & 0xFF) as u8;
    let prog_if = ((class_reg >> 8) & 0xFF) as u8;
    let subclass = ((class_reg >> 16) & 0xFF) as u8;
    let class = ((class_reg >> 24) & 0xFF) as u8;
    let header_reg = read32_unchecked(bus, device_num, function, CFG_CACHE_LINE_SIZE as u8);
    let header_type_raw = ((header_reg >> 16) & 0xFF) as u8;
    let multifunction = (header_type_raw & HDR_TYPE_MULTIFUNCTION) != 0;
    let header_type = HeaderType::from(header_type_raw);
    let subsys_reg = read32_unchecked(bus, device_num, function, CFG_SUBSYSTEM_VENDOR_ID as u8);
    let subsystem_vendor_id = (subsys_reg & 0xFFFF) as u16;
    let subsystem_id = ((subsys_reg >> 16) & 0xFFFF) as u16;
    let int_reg = read32_unchecked(bus, device_num, function, CFG_INTERRUPT_LINE as u8);
    let interrupt_line = (int_reg & 0xFF) as u8;
    let interrupt_pin = ((int_reg >> 8) & 0xFF) as u8;
    let address = PciAddress::new(bus, device_num, function);
    let config = ConfigSpace::new(address);
    let bars = decode_all_bars_unchecked(bus, device_num, function);
    let capabilities = collect_all_capabilities(&config).unwrap_or_default();
    let pcie_capabilities = enumerate_pcie_capabilities(bus, device_num, function);
    let msi = get_msi_info(&config).ok().flatten();
    let msix = get_msix_info(&config).ok().flatten();
    let power_management = get_power_management_info(&config).ok().flatten();
    let pcie = get_pcie_info(&config).ok().flatten();

    let mut device = PciDevice::new(address);
    device.device_id_info = DeviceId {
        vendor_id,
        device_id,
        subsystem_vendor_id,
        subsystem_id,
        revision,
    };
    device.class_code = ClassCode::new(class, subclass, prog_if);
    device.header_type = header_type;
    device.multifunction = multifunction;
    device.bars = bars;
    device.capabilities = capabilities;
    device.pcie_capabilities = pcie_capabilities;
    device.interrupt_line = interrupt_line;
    device.interrupt_pin = interrupt_pin;
    device.msi = msi;
    device.msix = msix;
    device.power_management = power_management;
    device.pcie = pcie;

    device.sync_compat_fields();

    stats::record_device_found(
        class,
        vendor_id,
        device.is_bridge(),
        device.is_pcie(),
        device.supports_msi(),
        device.supports_msix(),
        is_dma_capable(&device),
    );

    Some(device)
}

fn enumerate_bus(bus: u8, devices: &mut Vec<PciDevice>) {
    for device_num in 0..32u8 {
        let id = read32_unchecked(bus, device_num, 0, CFG_VENDOR_ID as u8);
        let vendor_id = (id & 0xFFFF) as u16;
        if vendor_id == 0xFFFF || vendor_id == 0x0000 {
            continue;
        }

        let header_reg = read32_unchecked(bus, device_num, 0, CFG_CACHE_LINE_SIZE as u8);
        let header_type = ((header_reg >> 16) & 0xFF) as u8;
        let multifunction = (header_type & HDR_TYPE_MULTIFUNCTION) != 0;
        if let Some(dev) = probe_device(bus, device_num, 0) {
            devices.push(dev);
        }

        if multifunction {
            for function in 1..8u8 {
                if let Some(dev) = probe_device(bus, device_num, function) {
                    devices.push(dev);
                }
            }
        }
    }
}

fn enumerate_all_buses() -> Vec<PciDevice> {
    let mut devices = Vec::new();

    for bus in 0..=255u8 {
        enumerate_bus(bus, &mut devices);
    }

    devices
}

pub fn init_pci() -> Result<()> {
    if PCI_MANAGER.is_completed() {
        return Err(PciError::AlreadyInitialized);
    }

    let devices = enumerate_all_buses();

    if devices.is_empty() {
        return Err(PciError::NoDevicesFound);
    }

    let device_count = devices.len();

    PCI_MANAGER.call_once(|| {
        Mutex::new(PciManager {
            devices,
            initialized: true,
        })
    });

    crate::log::logger::log_critical(&alloc::format!(
        "PCI subsystem initialized: {} devices found",
        device_count
    ));

    Ok(())
}

pub fn get_pci_manager() -> Option<&'static Mutex<PciManager>> {
    PCI_MANAGER.get()
}

pub fn is_initialized() -> bool {
    PCI_MANAGER.is_completed()
}

pub fn scan_and_collect() -> Vec<PciDevice> {
    if let Some(mgr) = get_pci_manager() {
        mgr.lock().devices.clone()
    } else {
        enumerate_all_buses()
    }
}

pub fn scan_and_collect_safe() -> Result<Vec<PciDevice>> {
    Ok(scan_and_collect())
}

pub fn find_device_by_class(class: u8, subclass: u8) -> Option<PciDevice> {
    scan_and_collect()
        .into_iter()
        .find(|d| d.class() == class && d.subclass() == subclass)
}

pub fn find_device_by_id(vendor_id: u16, device_id: u16) -> Option<PciDevice> {
    scan_and_collect()
        .into_iter()
        .find(|d| d.vendor_id() == vendor_id && d.device_id_value() == device_id)
}

pub fn with_manager<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&PciManager) -> R,
{
    get_pci_manager().map(|m| f(&m.lock()))
}

pub fn get_device_by_address(bus: u8, device: u8, function: u8) -> Option<PciDevice> {
    with_manager(|mgr| {
        mgr.find_by_address(bus, device, function).cloned()
    }).flatten()
}

pub fn get_device_by_class(class: u8, subclass: u8) -> Option<PciDevice> {
    with_manager(|mgr| {
        mgr.find_by_class(class, subclass).cloned()
    }).flatten()
}

pub fn count_devices() -> usize {
    with_manager(|mgr| mgr.device_count()).unwrap_or(0)
}

pub fn get_pci_stats() -> PciStats {
    with_manager(|mgr| mgr.get_stats()).unwrap_or_else(PciStats::new)
}
