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

use super::ahci::{init_ahci, AhciError};
use super::nvme::{init_nvme, NvmeError};
use super::virtio_blk::api::init as init_virtio_blk;

pub fn init_storage_drivers() {
    init_ahci_driver();
    init_nvme_driver();
    init_virtio_blk_driver();
}

fn init_ahci_driver() {
    crate::log_info!("[AHCI] Probing for SATA controllers...");
    match init_ahci() {
        Ok(()) => crate::log::logger::log_critical("✓ AHCI SATA controller initialized"),
        Err(AhciError::NoControllerFound) => crate::log_info!("[AHCI] No AHCI controller found"),
        Err(e) => crate::log_warn!("[AHCI] SATA init error: {:?}", e),
    }
}

fn init_nvme_driver() {
    crate::log_info!("[NVMe] Probing for NVMe controllers...");
    match init_nvme() {
        Ok(()) => crate::log::logger::log_critical("✓ NVMe storage controller initialized"),
        Err(NvmeError::NoControllerFound) => crate::log_info!("[NVMe] No NVMe controller found"),
        Err(e) => crate::log_warn!("[NVMe] NVMe init error: {:?}", e),
    }
}

fn init_virtio_blk_driver() {
    crate::log_info!("[VIRTIO-BLK] Probing for VirtIO block devices...");
    match init_virtio_blk() {
        Ok(()) => crate::log::logger::log_critical("✓ VirtIO block device initialized"),
        Err(e) => crate::log_info!("[VIRTIO-BLK] VirtIO block not available: {}", e),
    }
}
