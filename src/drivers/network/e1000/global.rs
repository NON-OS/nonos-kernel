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

use super::core::E1000;
use crate::bus::pci::{find_device, PciDevice};
use crate::network::stack::SmolDevice;
use crate::sys::serial;

static E1000_DRIVER: spin::Once<E1000> = spin::Once::new();
static E1000_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn find_e1000_device() -> Option<PciDevice> {
    find_device(0x02, 0x00, None)
}

pub fn init() -> Result<(), &'static str> {
    serial::println(b"[E1000] Probing for Intel NIC...");

    if E1000_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let mut driver = match E1000::new() {
        Some(d) => d,
        None => {
            serial::println(b"[E1000] No compatible NIC found");
            return Err("No e1000 found");
        }
    };

    driver.init()?;

    E1000_DRIVER.call_once(|| driver);
    E1000_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

pub fn is_initialized() -> bool {
    E1000_INITIALIZED.load(Ordering::SeqCst)
}

pub fn get_driver() -> Option<&'static dyn SmolDevice> {
    E1000_DRIVER.get().map(|e| e as &'static dyn SmolDevice)
}

pub fn poll() {
    if let Some(driver) = E1000_DRIVER.get() {
        driver.poll_rx();
    }
}
