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
use core::sync::atomic::{AtomicBool, Ordering};
use spin::RwLock;
use super::device::PciDevice;
use super::error::{PciError, PciResult};
use super::scan_core::scan_pci_bus;

pub static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static DEVICE_CACHE: RwLock<Vec<PciDevice>> = RwLock::new(Vec::new());

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

pub fn get_cached_devices() -> Vec<PciDevice> {
    DEVICE_CACHE.read().clone()
}
