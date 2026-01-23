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
use core::sync::atomic::{AtomicBool, Ordering};
use spin::RwLock;

use super::constants::{MAX_DEVICES_PER_BUS, MAX_FUNCTIONS_PER_DEVICE, MAX_PCI_BUSES};
use super::device::PciDevice;
use super::error::{PciError, PciResult};
use super::stats::PCI_STATS;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static DEVICE_CACHE: RwLock<Vec<PciDevice>> = RwLock::new(Vec::new());

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

pub fn init() -> PciResult<()> {
    if INITIALIZED.swap(true, Ordering::AcqRel) {
        return Err(PciError::AlreadyInitialized);
    }

    let devices = scan_pci_bus()?;
    crate::log::info!("PCI: found {} devices", devices.len());

    Ok(())
}

pub fn scan_pci_bus() -> PciResult<Vec<PciDevice>> {
    let mut devices = Vec::with_capacity(256);

    for bus in 0..MAX_PCI_BUSES as u8 {
        for slot in 0..MAX_DEVICES_PER_BUS {
            if let Some(device) = PciDevice::new(bus, slot, 0) {
                devices.push(device);

                if device.multifunction {
                    for function in 1..MAX_FUNCTIONS_PER_DEVICE {
                        if let Some(mf_device) = PciDevice::new(bus, slot, function) {
                            devices.push(mf_device);
                        }
                    }
                }
            }
        }
    }

    update_device_cache(&devices);
    Ok(devices)
}

fn update_device_cache(devices: &[PciDevice]) {
    let mut stats = PCI_STATS.write();
    stats.total_devices = devices.len();
    stats.devices_by_class.clear();
    stats.msix_devices = 0;

    for device in devices {
        *stats.devices_by_class.entry(device.class_code).or_insert(0) += 1;
        if device.has_msix() {
            stats.msix_devices += 1;
        }
    }

    let mut cache = DEVICE_CACHE.write();
    cache.clear();
    cache.extend_from_slice(devices);
}

pub fn get_cached_devices() -> Vec<PciDevice> {
    DEVICE_CACHE.read().clone()
}

pub fn find_device(vendor_id: u16, device_id: u16) -> Option<PciDevice> {
    DEVICE_CACHE.read().iter()
        .find(|d| d.vendor_id == vendor_id && d.device_id == device_id)
        .copied()
}

pub fn find_devices_by_class(class_code: u8) -> Vec<PciDevice> {
    DEVICE_CACHE.read().iter()
        .filter(|d| d.class_code == class_code)
        .copied()
        .collect()
}

pub fn find_devices_by_class_subclass(class_code: u8, subclass: u8) -> Vec<PciDevice> {
    DEVICE_CACHE.read().iter()
        .filter(|d| d.class_code == class_code && d.subclass == subclass)
        .copied()
        .collect()
}
