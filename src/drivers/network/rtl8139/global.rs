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

use super::constants::{RTL8139_DEVICE_ID, RTL8139_VENDOR_ID};
use super::core::Rtl8139;
use crate::bus::pci::{find_device_by_id, PciDevice};
use crate::network::stack::SmolDevice;
use crate::sys::serial;

static RTL8139_DRIVER: spin::Once<Rtl8139> = spin::Once::new();
static RTL8139_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn find_rtl8139_device() -> Option<PciDevice> {
    find_device_by_id(RTL8139_VENDOR_ID, RTL8139_DEVICE_ID)
}

pub fn init() -> Result<(), &'static str> {
    serial::println(b"[RTL8139] Probing for Realtek NIC...");

    if RTL8139_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let mut driver = match Rtl8139::new() {
        Some(d) => d,
        None => {
            serial::println(b"[RTL8139] No compatible NIC found");
            return Err("No RTL8139 found");
        }
    };

    driver.init()?;

    RTL8139_DRIVER.call_once(|| driver);
    RTL8139_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

pub fn is_initialized() -> bool {
    RTL8139_INITIALIZED.load(Ordering::SeqCst)
}

pub fn get_driver() -> Option<&'static dyn SmolDevice> {
    RTL8139_DRIVER.get().map(|d| d as &'static dyn SmolDevice)
}

pub fn poll() {
    if let Some(d) = RTL8139_DRIVER.get() {
        d.poll_rx();
    }
}
