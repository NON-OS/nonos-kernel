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

use core::sync::atomic::{AtomicBool, Ordering};

use super::constants::{VIRTIO_NET_DEVICE_ID, VIRTIO_NET_MODERN_ID, VIRTIO_VENDOR_ID};
use super::core::VirtioNet;
use crate::bus::pci::{find_device_by_id, PciDevice};
use crate::network::stack::SmolDevice;
use crate::sys::serial;

static VIRTIO_DRIVER: spin::Once<VirtioNet> = spin::Once::new();
static VIRTIO_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn find_virtio_net_device() -> Option<PciDevice> {
    find_device_by_id(VIRTIO_VENDOR_ID, VIRTIO_NET_DEVICE_ID)
        .or_else(|| find_device_by_id(VIRTIO_VENDOR_ID, VIRTIO_NET_MODERN_ID))
}

pub fn init() -> Result<(), &'static str> {
    serial::println(b"[VIRTIO-NET] Probing for VirtIO NIC...");

    if VIRTIO_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let mut driver = match VirtioNet::new() {
        Some(d) => d,
        None => {
            serial::println(b"[VIRTIO-NET] No compatible NIC found");
            return Err("No virtio-net found");
        }
    };

    driver.init()?;

    VIRTIO_DRIVER.call_once(|| driver);
    VIRTIO_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

pub fn is_initialized() -> bool {
    VIRTIO_INITIALIZED.load(Ordering::SeqCst)
}

pub fn get_driver() -> Option<&'static dyn SmolDevice> {
    VIRTIO_DRIVER.get().map(|v| v as &'static dyn SmolDevice)
}

pub fn poll() {
    if let Some(driver) = VIRTIO_DRIVER.get() {
        driver.poll_rx();
    }
}
