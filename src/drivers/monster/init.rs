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

use super::stats::{record_error, refresh_stats};
use core::sync::atomic::{AtomicBool, Ordering};

static MONSTER_INITED: AtomicBool = AtomicBool::new(false);

pub fn init() -> Result<(), &'static str> {
    if MONSTER_INITED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }

    if let Err(e) = crate::drivers::pci::init_pci() {
        crate::log::logger::log_warn!("MONSTER: PCI init failed: {}", e);
        record_error();
        MONSTER_INITED.store(false, Ordering::Release);
        return Err("MONSTER: PCI initialization failed (required)");
    }

    if let Err(e) = crate::drivers::nvme::init_nvme() {
        crate::log::logger::log_warn!("MONSTER: NVMe init skipped/failed: {}", e);
        record_error();
    }

    match crate::drivers::xhci::init_xhci() {
        Ok(_) => {
            if let Err(e) = crate::drivers::usb::init_usb() {
                crate::log::logger::log_warn!("MONSTER: USB init skipped/failed: {}", e);
                record_error();
            }
        }
        Err(e) => {
            crate::log::logger::log_warn!("MONSTER: xHCI init skipped/failed: {}", e);
            record_error();
        }
    }

    if let Err(e) = crate::drivers::virtio_net::init_virtio_net() {
        crate::log::logger::log_warn!("MONSTER: virtio-net init skipped/failed: {}", e);
        record_error();
    }

    if let Err(e) = crate::drivers::gpu::init_gpu() {
        crate::log::logger::log_warn!("MONSTER: GPU init skipped/failed: {}", e);
        record_error();
    }

    if let Err(e) = crate::drivers::audio::init_hd_audio() {
        crate::log::logger::log_warn!("MONSTER: HD Audio init skipped/failed: {}", e);
        record_error();
    }

    refresh_stats();
    crate::log::logger::log_critical("✓ MONSTER orchestrator initialized");
    Ok(())
}

#[inline]
pub fn is_initialized() -> bool {
    MONSTER_INITED.load(Ordering::Relaxed)
}

pub fn self_test() -> Result<(), &'static str> {
    if let Some(surf) = crate::drivers::gpu::GpuDriver::get_surface() {
        surf.fill_rect(0, 0, 8, 8, 0x00000000);
        surf.present(Some((0, 0, 8, 8)));
    }

    refresh_stats();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_initialized() {
        let _ = is_initialized();
    }
}
