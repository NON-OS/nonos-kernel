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

use crate::drivers::pci::config::ConfigSpace;
use crate::drivers::pci::types::PciBar;

use super::super::controller::DesignWareI2c;
use super::super::CONTROLLERS;
use super::constants::{INTEL_VENDOR_ID, LPSS_I2C_DEVICE_IDS};
use super::controller::LpssController;

pub fn find_lpss_controllers() -> Vec<LpssController> {
    let mut controllers = Vec::new();
    let pci_devices = crate::drivers::pci::scan_and_collect();

    for pci_dev in pci_devices {
        if pci_dev.vendor_id() != INTEL_VENDOR_ID {
            continue;
        }

        let device_id = pci_dev.device_id_value();

        if let Some((_, name, clock)) = LPSS_I2C_DEVICE_IDS
            .iter()
            .find(|(id, _, _)| *id == device_id)
        {
            let base = match &pci_dev.bars[0] {
                PciBar::Memory32 { address, .. } => address.as_u64(),
                PciBar::Memory64 { address, .. } => address.as_u64(),
                PciBar::Memory { address, .. } => address.as_u64(),
                _ => continue,
            };

            if base == 0 {
                continue;
            }

            let config = ConfigSpace::new(pci_dev.address);
            let _ = config.set_power_state_d0();
            let _ = config.enable_bus_master();
            let _ = config.enable_memory_space();

            let mut dw = match DesignWareI2c::new(base, *clock) {
                Some(d) => d,
                None => {
                    crate::log_warn!("i2c: Failed to map MMIO at 0x{:x}", base);
                    continue;
                }
            };

            if dw.init().is_ok() {
                let index = controllers.len();
                controllers.push(LpssController {
                    inner: dw,
                    bus: pci_dev.bus(),
                    device: pci_dev.device(),
                    function: pci_dev.function(),
                    device_id,
                    name,
                    index,
                });

                crate::log::info!(
                    "i2c: Found {} at {:02x}:{:02x}.{} (BAR 0x{:x})",
                    name,
                    pci_dev.bus(),
                    pci_dev.device(),
                    pci_dev.function(),
                    base
                );
            }
        }
    }

    controllers
}

pub fn init() -> usize {
    let controllers = find_lpss_controllers();
    let count = controllers.len();

    let mut global = CONTROLLERS.lock();
    *global = controllers;

    if count > 0 {
        crate::log::info!("i2c: Initialized {} Intel LPSS I2C controller(s)", count);
    }

    count
}

pub fn scan_bus(controller: usize) -> Vec<u8> {
    let mut found = Vec::new();

    if let Some(ctrl) = super::super::get_controller(controller) {
        for addr in 0x08..0x78 {
            if ctrl.probe(addr) {
                found.push(addr);
            }
        }
    }

    found
}
