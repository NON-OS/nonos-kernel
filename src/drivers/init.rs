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

use super::init_dma::init_dma_subsystem;
use super::init_storage::init_storage_drivers;
use super::init_network::init_network_drivers;
use super::init_peripherals::init_peripheral_drivers;

pub fn init_all_drivers() -> Result<(), &'static str> {
    init_dma_subsystem()?;
    init_entropy();
    init_gpu_driver();
    init_monster();
    init_peripheral_drivers();
    init_storage_drivers();
    init_network_drivers();
    Ok(())
}

fn init_entropy() {
    match super::init_virtio_rng() {
        Ok(()) => crate::log::logger::log_critical("✓ VirtIO-RNG hardware entropy source initialized"),
        Err(e) => crate::log_info!("[DRV] VirtIO-RNG not available: {} (will use CPU entropy)", e),
    }
}

fn init_gpu_driver() {
    match super::gpu::api::init_gpu() {
        Ok(()) => crate::log::logger::log_critical("✓ GPU (Bochs VBE) initialized"),
        Err(e) => crate::log_info!("[GPU] GPU init skipped: {}", e),
    }
}

fn init_monster() {
    crate::log::logger::log_critical("Initializing NONOS driver stack via MONSTER orchestrator...");
    let _ = super::monster::monster_init();
    crate::log::logger::log_critical("✓ NONOS driver stack initialized");
}
