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

use alloc::vec::Vec;
use super::constants::{MAX_DEVICES_PER_BUS, MAX_FUNCTIONS_PER_DEVICE, MAX_PCI_BUSES};
use super::device::PciDevice;
use super::error::PciResult;
use super::scan_state::DEVICE_CACHE;
use super::stats::PCI_STATS;

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
        if device.has_msix() { stats.msix_devices += 1; }
    }
    let mut cache = DEVICE_CACHE.write();
    cache.clear();
    cache.extend_from_slice(devices);
}
