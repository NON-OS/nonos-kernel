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

use super::types::{NvmeController, NvmeNamespace};
use super::driver::scan_pci_for_nvme;
use crate::storage::StorageManager;
use crate::storage::block_device::RamDisk;

static NVME_STATE: Mutex<NvmeState> = Mutex::new(NvmeState::new());

struct NvmeState {
    controllers: Vec<NvmeController>,
    namespaces: Vec<NvmeNamespace>,
    initialized: bool,
}

impl NvmeState {
    const fn new() -> Self {
        Self {
            controllers: Vec::new(),
            namespaces: Vec::new(),
            initialized: false,
        }
    }
}

pub fn init() -> Result<(), &'static str> {
    let mut state = NVME_STATE.lock();
    if state.initialized {
        return Ok(());
    }

    crate::log::info!("nvme: Scanning for NVMe controllers...");

    let NvmeState { controllers, namespaces, .. } = &mut *state;
    scan_pci_for_nvme(controllers, namespaces);

    if state.controllers.is_empty() {
        crate::log::info!("nvme: No NVMe controllers found");
    } else {
        for ctrl in &state.controllers {
            crate::log::info!(
                "nvme: Found controller at {:02x}:{:02x}.{} (vendor={:04x} device={:04x})",
                ctrl.bus, ctrl.device, ctrl.function,
                ctrl.vendor_id, ctrl.device_id
            );
            crate::log::info!(
                "nvme:   version={}.{}.{} max_qe={} stride={}",
                (ctrl.version >> 16) & 0xFFFF,
                (ctrl.version >> 8) & 0xFF,
                ctrl.version & 0xFF,
                ctrl.max_queue_entries,
                ctrl.doorbell_stride
            );
            if !ctrl.model_number.is_empty() {
                crate::log::info!("nvme:   Model: {} SN: {} FW: {}",
                    ctrl.model_number, ctrl.serial_number, ctrl.firmware_rev);
            }
        }

        for ns in &state.namespaces {
            let capacity_gb = ns.capacity_bytes / (1024 * 1024 * 1024);
            crate::log::info!(
                "nvme:   Namespace {}: {} blocks x {} bytes = {} GB",
                ns.nsid, ns.size_blocks, ns.block_size, capacity_gb
            );
        }
    }

    crate::log::info!("nvme: ZeroState mode - detected devices registered but not mounted");
    state.initialized = true;
    Ok(())
}

pub fn scan_and_register_nvme_devices(manager: &StorageManager) -> Result<(), &'static str> {
    let state = NVME_STATE.lock();

    if !state.controllers.is_empty() {
        let total_capacity: u64 = state.namespaces.iter()
            .map(|ns| ns.capacity_bytes)
            .sum();

        crate::log::info!(
            "nvme: Found {} controllers with {} namespaces ({} GB total) - ZeroState: using RamDisk",
            state.controllers.len(),
            state.namespaces.len(),
            total_capacity / (1024 * 1024 * 1024)
        );
    }

    RamDisk::ensure_default_registered(manager);

    Ok(())
}

pub fn get_controllers() -> Vec<NvmeController> {
    NVME_STATE.lock().controllers.clone()
}

pub fn get_namespaces() -> Vec<NvmeNamespace> {
    NVME_STATE.lock().namespaces.clone()
}

pub fn has_nvme_hardware() -> bool {
    !NVME_STATE.lock().controllers.is_empty()
}

pub fn get_stats() -> (usize, usize, u64) {
    let state = NVME_STATE.lock();
    let total_capacity: u64 = state.namespaces.iter()
        .map(|ns| ns.capacity_bytes)
        .sum();
    (state.controllers.len(), state.namespaces.len(), total_capacity)
}

pub fn get_total_capacity() -> u64 {
    NVME_STATE.lock().namespaces.iter()
        .map(|ns| ns.capacity_bytes)
        .sum()
}
