// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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


use super::{
    init_e1000, init_rtl8139, init_tpm, init_wifi, print_wifi_status, TpmError,
};

pub fn init_all_drivers() -> Result<(), &'static str> {
    crate::memory::dma::init_dma_allocator()
        .map_err(|_| "Failed to initialize DMA allocator")?;
    let _ = crate::memory::dma::create_dma_pool(4096, 128, crate::memory::dma::DmaConstraints::default());
    let _ = crate::memory::dma::create_dma_pool(2048, 256, crate::memory::dma::DmaConstraints::default());

    crate::log::logger::log_critical("Initializing NONOS driver stack via MONSTER orchestrator...");
    super::monster::monster_init()?;
    crate::log::logger::log_critical("✓ NONOS driver stack initialized");

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

    crate::log_info!("[NET] Probing for hardware network adapters...");

    match init_e1000() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ Intel E1000 Ethernet initialized");
        }
        Err(_) => {}
    }

    match init_rtl8139() {
        Ok(()) => {
            crate::log::logger::log_critical("✓ Realtek RTL8139 Ethernet initialized");
        }
        Err(_) => {}
    }

    let wifi_count = init_wifi();
    if wifi_count > 0 {
        crate::log_info!("[WIFI] Found {} WiFi adapter(s)", wifi_count);
        print_wifi_status();
    }

    Ok(())
}
