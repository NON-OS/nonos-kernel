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

use super::constants::{RTL8168_DEVICE_ID, RTL8169_DEVICE_ID, RTL8169_VENDOR_ID};
use super::core::Rtl8169;
use crate::bus::pci::{find_device_by_id, PciDevice};
use crate::network::stack::SmolDevice;
use crate::sys::serial;

static RTL8169_DRIVER: spin::Once<Rtl8169> = spin::Once::new();
static RTL8169_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn find_rtl8169_device() -> Option<PciDevice> {
    find_device_by_id(RTL8169_VENDOR_ID, RTL8169_DEVICE_ID)
        .or_else(|| find_device_by_id(RTL8169_VENDOR_ID, RTL8168_DEVICE_ID))
}

pub fn init() -> Result<(), &'static str> {
    serial::println(b"[RTL8169] Probing for Realtek Gigabit NIC...");

    if RTL8169_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let mut driver = match Rtl8169::new() {
        Some(d) => d,
        None => {
            serial::println(b"[RTL8169] No compatible NIC found");
            return Err("No RTL8169 found");
        }
    };

    driver.init()?;

    RTL8169_DRIVER.call_once(|| driver);
    RTL8169_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

pub fn is_initialized() -> bool {
    RTL8169_INITIALIZED.load(Ordering::SeqCst)
}

pub fn get_driver() -> Option<&'static dyn SmolDevice> {
    RTL8169_DRIVER.get().map(|d| d as &'static dyn SmolDevice)
}

pub fn poll() {
    if let Some(d) = RTL8169_DRIVER.get() {
        d.poll_rx();
    }
}
