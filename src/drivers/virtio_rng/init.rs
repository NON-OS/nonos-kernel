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
use crate::bus::pci;
use crate::sys::serial;
use super::device::VirtioRngDevice;
use super::{VIRTIO_RNG, VIRTIO_RNG_AVAILABLE, VIRTIO_VENDOR_ID};
use super::{VIRTIO_RNG_DEVICE_ID_TRANSITIONAL, VIRTIO_RNG_DEVICE_ID_MODERN};

pub fn init() -> Result<(), &'static str> {
    if !pci::is_init() {
        return Err("virtio-rng: PCI not initialized");
    }

    let count = pci::device_count();
    for i in 0..count {
        let dev = match pci::get_device(i) {
            Some(d) => d,
            None => continue,
        };

        if dev.vendor_id == VIRTIO_VENDOR_ID
            && (dev.device_id == VIRTIO_RNG_DEVICE_ID_TRANSITIONAL
                || dev.device_id == VIRTIO_RNG_DEVICE_ID_MODERN)
        {
            serial::print(b"[VIRTIO-RNG] Found at PCI ");
            serial::print_dec(dev.bus as u64);
            serial::print(b":");
            serial::print_dec(dev.device as u64);
            serial::print(b".");
            serial::print_dec(dev.function as u64);
            serial::println(b"");

            // Enable bus mastering for DMA and memory/IO space access
            pci::enable_bus_master(dev.bus, dev.device, dev.function);

            match VirtioRngDevice::from_bar0(dev.bar0) {
                Ok(rng_dev) => {
                    *VIRTIO_RNG.lock() = Some(rng_dev);
                    VIRTIO_RNG_AVAILABLE.store(true, Ordering::SeqCst);
                    return Ok(());
                }
                Err(e) => {
                    serial::print(b"[VIRTIO-RNG] Init failed: ");
                    serial::println(e.as_bytes());
                }
            }
        }
    }

    Err("virtio-rng: no device found")
}
