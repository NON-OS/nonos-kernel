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

use super::audio::{init_hd_audio, AudioError};
use super::usb::manager::init_usb;
use super::{init_tpm, TpmError};

pub fn init_peripheral_drivers() {
    init_i2c();
    init_tpm_driver();
    init_usb_subsystem();
    init_audio();
}

fn init_i2c() {
    let i2c_count = super::i2c::init();
    if i2c_count > 0 {
        crate::log_info!("[I2C] Initialized {} Intel LPSS I2C controller(s)", i2c_count);
    }
}

fn init_tpm_driver() {
    crate::log_info!("[TPM] Probing for TPM 2.0...");
    match init_tpm() {
        Ok(()) => crate::log::logger::log_critical("✓ TPM 2.0 initialized for measured boot"),
        Err(TpmError::NotPresent) => {
            crate::log_info!("[TPM] TPM not present (measured boot unavailable)")
        }
        Err(e) => crate::log_warn!("[TPM] TPM init error: {:?}", e),
    }
}

fn init_usb_subsystem() {
    crate::log_info!("[USB] Initializing USB subsystem...");
    match init_usb() {
        Ok(()) => crate::log::logger::log_critical("✓ USB subsystem initialized"),
        Err(e) => crate::log_info!("[USB] USB init skipped: {}", e),
    }
}

fn init_audio() {
    crate::log_info!("[HDA] Probing for HD Audio controllers...");
    match init_hd_audio() {
        Ok(()) => crate::log::logger::log_critical("✓ HD Audio controller initialized"),
        Err(AudioError::NoControllerFound) => {
            crate::log_info!("[HDA] No HD Audio controller found")
        }
        Err(e) => crate::log_warn!("[HDA] HD Audio init error: {:?}", e),
    }
}
