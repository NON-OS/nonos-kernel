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

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

use super::types::{AhciController, AhciPort, AhciDeviceType};
use super::probe::scan_pci_for_ahci;
use crate::storage::StorageManager;

static AHCI_STATE: Mutex<AhciState> = Mutex::new(AhciState::new());

struct AhciState {
    controllers: Vec<AhciController>,
    ports: Vec<AhciPort>,
    initialized: bool,
}

impl AhciState {
    const fn new() -> Self {
        Self {
            controllers: Vec::new(),
            ports: Vec::new(),
            initialized: false,
        }
    }
}

pub fn init() -> Result<(), &'static str> {
    let mut state = AHCI_STATE.lock();
    if state.initialized {
        return Ok(());
    }

    crate::log::info!("ahci: Scanning for AHCI controllers...");

    let AhciState { controllers, ports, .. } = &mut *state;
    scan_pci_for_ahci(controllers, ports);

    if state.controllers.is_empty() {
        crate::log::info!("ahci: No AHCI controllers found");
    } else {
        for ctrl in &state.controllers {
            crate::log::info!(
                "ahci: Found controller at {:02x}:{:02x}.{} (vendor={:04x} device={:04x})",
                ctrl.bus, ctrl.device, ctrl.function,
                ctrl.vendor_id, ctrl.device_id
            );
            crate::log::info!(
                "ahci:   version={}.{} ports={:08x} slots={} 64bit={} ncq={}",
                (ctrl.version >> 16) & 0xFFFF, ctrl.version & 0xFFFF,
                ctrl.ports_implemented, ctrl.command_slots,
                ctrl.supports_64bit, ctrl.supports_ncq
            );
        }

        for port in &state.ports {
            if port.device_type == AhciDeviceType::Sata {
                crate::log::info!(
                    "ahci:   Port {}: {} {} ({} sectors x {} bytes)",
                    port.port_num, port.model, port.serial,
                    port.size_sectors, port.sector_size
                );
            }
        }
    }

    crate::log::info!("ahci: ZeroState mode - detected devices registered but not mounted");
    state.initialized = true;
    Ok(())
}

pub fn scan_and_register_ahci_devices(_manager: &StorageManager) -> Result<(), &'static str> {
    let state = AHCI_STATE.lock();

    if !state.controllers.is_empty() {
        let sata_count = state.ports.iter()
            .filter(|p| p.device_type == AhciDeviceType::Sata)
            .count();

        crate::log::info!(
            "ahci: Found {} controllers with {} SATA devices (ZeroState: not mounting)",
            state.controllers.len(),
            sata_count
        );
    }

    Ok(())
}

pub fn get_controllers() -> Vec<AhciController> {
    AHCI_STATE.lock().controllers.clone()
}

pub fn get_ports() -> Vec<AhciPort> {
    AHCI_STATE.lock().ports.clone()
}

pub fn has_ahci_hardware() -> bool {
    !AHCI_STATE.lock().controllers.is_empty()
}

pub fn get_stats() -> (usize, usize, u64) {
    let state = AHCI_STATE.lock();
    let sata_devices = state.ports.iter()
        .filter(|p| p.device_type == AhciDeviceType::Sata)
        .count();
    let total_capacity: u64 = state.ports.iter()
        .filter(|p| p.device_type == AhciDeviceType::Sata)
        .map(|p| p.size_sectors * p.sector_size as u64)
        .sum();

    (state.controllers.len(), sata_devices, total_capacity)
}
