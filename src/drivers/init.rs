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


/* DEV NOTES eK@nonos.systems

Driver initialization orchestration for NONOS kernel. This module coordinates
the startup sequence for all hardware drivers. Order matters here because some
drivers depend on resources initialized by others (DMA pools, entropy sources).

The init sequence follows this order:
1. DMA allocator and pools for zero-copy I/O
2. VirtIO-RNG for early entropy (needed by crypto and network)
3. GPU driver for framebuffer graphics
4. MONSTER orchestrator for coordinated driver bringup
5. I2C controllers for sensor access
6. TPM for measured boot attestation
7. Storage: AHCI (SATA), NVMe, VirtIO-blk
8. Network adapters: E1000, RTL8139, RTL8168, VirtIO-net
9. WiFi adapters
10. USB subsystem with class drivers
11. HD Audio controller

Each driver init is non-fatal on failure except DMA which is required.
*/

use super::{
    init_e1000, init_rtl8139, init_rtl8168, init_tpm, init_wifi, print_wifi_status, TpmError,
    init_virtio_rng,
};
use super::ahci::{init_ahci, AhciError};
use super::nvme::{init_nvme, NvmeError};
use super::audio::{init_hd_audio, AudioError};
use super::gpu::api::init_gpu;
use super::usb::manager::global::init_usb;
use super::virtio_blk::api::init as init_virtio_blk;
use super::virtio_net::api::init_virtio_net;

pub fn init_all_drivers() -> Result<(), &'static str> {
    crate::memory::dma::init_dma_allocator()
        .map_err(|_| "Failed to initialize DMA allocator")?;
    let _ = crate::memory::dma::create_dma_pool(4096, 128, crate::memory::dma::DmaConstraints::default());
    let _ = crate::memory::dma::create_dma_pool(2048, 256, crate::memory::dma::DmaConstraints::default());

    crate::log_info!("[DRV] Probing for VirtIO-RNG device...");
    match init_virtio_rng() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ VirtIO-RNG hardware entropy source initialized");
        }
        Err(e) => {
            crate::log_info!("[DRV] VirtIO-RNG not available: {} (will use CPU entropy)", e);
        }
    }

    crate::log_info!("[GPU] Probing for GPU/VBE...");
    match init_gpu() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ GPU (Bochs VBE) initialized");
        }
        Err(e) => {
            crate::log_info!("[GPU] GPU init skipped: {}", e);
        }
    }

    crate::log::logger::log_critical("Initializing NONOS driver stack via MONSTER orchestrator...");
    super::monster::monster_init()?;
    crate::log::logger::log_critical("✓ NONOS driver stack initialized");

    let i2c_count = super::i2c::init();
    if i2c_count > 0 {
        crate::log_info!("[I2C] Initialized {} Intel LPSS I2C controller(s)", i2c_count);
    }

    crate::log_info!("[TPM] Probing for TPM 2.0...");
    match init_tpm() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ TPM 2.0 initialized for measured boot");
        }
        Err(TpmError::NotPresent) => {
            crate::log_info!("[TPM] TPM not present (measured boot unavailable)");
        }
        Err(e) => {
            crate::log_warn!("[TPM] TPM init error: {:?}", e);
        }
    }

    crate::log_info!("[AHCI] Probing for SATA controllers...");
    match init_ahci() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ AHCI SATA controller initialized");
        }
        Err(AhciError::NoControllerFound) => {
            crate::log_info!("[AHCI] No AHCI controller found (legacy or NVMe-only system)");
        }
        Err(e) => {
            crate::log_warn!("[AHCI] SATA init error: {:?}", e);
        }
    }

    crate::log_info!("[NVMe] Probing for NVMe controllers...");
    match init_nvme() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ NVMe storage controller initialized");
        }
        Err(NvmeError::NoControllerFound) => {
            crate::log_info!("[NVMe] No NVMe controller found");
        }
        Err(e) => {
            crate::log_warn!("[NVMe] NVMe init error: {:?}", e);
        }
    }

    crate::log_info!("[VIRTIO-BLK] Probing for VirtIO block devices...");
    match init_virtio_blk() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ VirtIO block device initialized");
        }
        Err(e) => {
            crate::log_info!("[VIRTIO-BLK] VirtIO block not available: {}", e);
        }
    }

    crate::log_info!("[NET] Probing for hardware network adapters...");
    let mut eth_count = 0u8;

    match init_e1000() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ Intel E1000 Ethernet initialized");
            eth_count += 1;
        }
        Err(e) => {
            crate::log_info!("[E1000] Not found or init failed: {}", e);
        }
    }

    match init_rtl8139() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ Realtek RTL8139 Ethernet initialized");
            eth_count += 1;
        }
        Err(e) => {
            crate::log_info!("[RTL8139] Not found or init failed: {}", e);
        }
    }

    match init_rtl8168() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ Realtek RTL8168 Gigabit Ethernet initialized");
            eth_count += 1;
        }
        Err(e) => {
            crate::log_info!("[RTL8168] Not found or init failed: {}", e);
        }
    }

    match init_virtio_net() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ VirtIO-net initialized");
            eth_count += 1;
        }
        Err(e) => {
            crate::log_info!("[VIRTIO-NET] VirtIO-net not available: {}", e);
        }
    }

    if eth_count == 0 {
        crate::log_warn!("[NET] No Ethernet adapters detected - check PCI/drivers");
    } else {
        crate::log_info!("[NET] {} Ethernet adapter(s) ready", eth_count);
    }

    let wifi_count = init_wifi();
    if wifi_count > 0 {
        crate::log_info!("[WIFI] Found {} WiFi adapter(s)", wifi_count);
        print_wifi_status();
    } else {
        crate::log_info!("[WIFI] No WiFi adapters detected");
    }

    crate::log_info!("[USB] Initializing USB subsystem...");
    match init_usb() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ USB subsystem initialized");
        }
        Err(e) => {
            crate::log_info!("[USB] USB init skipped: {}", e);
        }
    }

    crate::log_info!("[HDA] Probing for HD Audio controllers...");
    match init_hd_audio() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ HD Audio controller initialized");
        }
        Err(AudioError::NoControllerFound) => {
            crate::log_info!("[HDA] No HD Audio controller found");
        }
        Err(e) => {
            crate::log_warn!("[HDA] HD Audio init error: {:?}", e);
        }
    }

    Ok(())
}
