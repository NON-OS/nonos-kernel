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

use core::sync::atomic::Ordering;
use crate::drivers::pci::get_pci_manager;
use super::device::VirtioRngDevice;
use super::{VIRTIO_RNG, VIRTIO_RNG_AVAILABLE, VIRTIO_VENDOR_ID};
use super::{VIRTIO_RNG_DEVICE_ID_TRANSITIONAL, VIRTIO_RNG_DEVICE_ID_MODERN};

pub fn init() -> Result<(), &'static str> {
    let manager = get_pci_manager().ok_or("PCI manager not available")?;
    let guard = manager.lock();
    let devices = guard.devices();

    for dev in devices.iter() {
        if dev.vendor_id == VIRTIO_VENDOR_ID
            && (dev.device_id == VIRTIO_RNG_DEVICE_ID_TRANSITIONAL
                || dev.device_id == VIRTIO_RNG_DEVICE_ID_MODERN)
        {
            match VirtioRngDevice::new(dev) {
                Ok(rng_dev) => {
                    *VIRTIO_RNG.lock() = Some(rng_dev);
                    VIRTIO_RNG_AVAILABLE.store(true, Ordering::SeqCst);
                    crate::log::info!("virtio-rng: initialized");
                    return Ok(());
                }
                Err(_) => {}
            }
        }
    }

    Err("virtio-rng: no device found")
}
