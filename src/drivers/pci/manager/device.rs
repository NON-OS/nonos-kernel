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

extern crate alloc;

use alloc::vec::Vec;

use super::super::stats::PciStats;
use super::super::types::PciDevice;

pub struct PciManager {
    pub(super) devices: Vec<PciDevice>,
    pub(super) initialized: bool,
}

impl PciManager {
    pub(super) fn new() -> Self {
        Self {
            devices: Vec::new(),
            initialized: false,
        }
    }

    pub(super) fn with_devices(devices: Vec<PciDevice>) -> Self {
        let mut mgr = Self::new();
        mgr.devices = devices;
        mgr.initialized = true;
        mgr
    }

    pub fn is_ready(&self) -> bool {
        self.initialized
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
