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
use spin::{Mutex, Once};

use super::super::error::{PciError, Result};
use super::super::stats::PciStats;
use super::super::types::PciDevice;
use super::device::PciManager;
use super::probe::enumerate_all_buses;

static PCI_MANAGER: Once<Mutex<PciManager>> = Once::new();

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
        Mutex::new(PciManager::with_devices(devices))
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
