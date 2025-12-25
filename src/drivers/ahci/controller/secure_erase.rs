// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! AHCI secure erase and verification operations.

use alloc::{format, collections::BTreeMap};
use spin::{Mutex, RwLock};
use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};
use crate::crypto::aes::Aes256;
use super::super::error::AhciError;
use super::super::types::AhciDevice;
use super::super::dma::PortDma;
use super::super::constants::*;
use super::commands;
use super::io::{find_free_slot, wait_complete_or_error};
use super::helpers::RegisterAccess;

/// Secure erase device implementation.
pub fn secure_erase_device<T: RegisterAccess>(
    ctrl: &T,
    ports: &RwLock<BTreeMap<u32, AhciDevice>>,
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    errors: &AtomicU64,
    port_resets: &AtomicU64,
    command_timeout: &AtomicU32,
    port: u32,
    enhanced: bool,
) -> Result<(), AhciError> {
    let devs = ports.read();
    let dev = devs.get(&port).ok_or(AhciError::PortNotInitialized)?;
    if !dev.supports_security_erase {
        return Err(AhciError::SecureEraseNotSupported);
    }
    drop(devs);

    crate::log::logger::log_critical(&format!(
        "AHCI: Starting {} secure erase on port {}",
        if enhanced { "ENHANCED" } else { "NORMAL" },
        port
    ));

    // Step 1: SECURITY ERASE PREPARE
    let slot = find_free_slot(ctrl, port)?;
    commands::build_security_erase_prepare_command(port_dma, port, slot)?;
    ctrl.write_port_reg(port, PORT_CI, 1 << slot);
    wait_complete_or_error(ctrl, errors, port_resets, command_timeout.load(Ordering::Relaxed), port, slot)?;

    // Step 2: SECURITY ERASE UNIT
    let slot = find_free_slot(ctrl, port)?;
    commands::build_security_erase_unit_command(port_dma, port, slot, enhanced)?;
    let old_timeout = command_timeout.swap(COMMAND_TIMEOUT_ERASE, Ordering::Relaxed);
    ctrl.write_port_reg(port, PORT_CI, 1 << slot);
    let result = wait_complete_or_error(ctrl, errors, port_resets, COMMAND_TIMEOUT_ERASE, port, slot);
    command_timeout.store(old_timeout, Ordering::Relaxed);
    result?;

    crate::log::logger::log_critical(&format!("AHCI: Secure erase completed on port {}", port));
    Ok(())
}

/// Verify erasure by sampling sectors.
pub fn verify_erasure<T: RegisterAccess>(
    ctrl: &T,
    ports: &RwLock<BTreeMap<u32, AhciDevice>>,
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    validation_failures: &AtomicU64,
    read_ops: &AtomicU64,
    bytes_read: &AtomicU64,
    errors: &AtomicU64,
    port_resets: &AtomicU64,
    encryption_enabled: &AtomicBool,
    aes_cipher: &Mutex<Option<Aes256>>,
    encryption_iv: &[u8; 16],
    command_timeout: u32,
    port: u32,
    sample_count: u32,
) -> Result<bool, AhciError> {
    let devs = ports.read();
    let dev = devs.get(&port).ok_or(AhciError::PortNotInitialized)?;
    let total_sectors = dev.sectors;
    drop(devs);

    let buf_dma_region = alloc_dma_coherent(512, DmaConstraints {
        alignment: 512,
        max_segment_size: 512,
        dma32_only: false,
        coherent: true,
    }).map_err(|_| AhciError::DmaAllocationFailed)?;

    let buf_va = buf_dma_region.virt_addr;

    for i in 0..sample_count {
        let lba = ((i as u64 * 7919) % total_sectors).min(total_sectors - 1);
        let old_enc = encryption_enabled.swap(false, Ordering::SeqCst);

        let result = super::io::read_sectors(
            ctrl, ports, port_dma, validation_failures, read_ops, bytes_read,
            errors, port_resets, encryption_enabled, aes_cipher, encryption_iv,
            command_timeout, port, lba, 1, buf_va.as_u64()
        );

        encryption_enabled.store(old_enc, Ordering::SeqCst);
        result?;

        let data = unsafe { core::slice::from_raw_parts(buf_va.as_ptr::<u8>(), 512) };
        if !data.iter().all(|&b| b == 0) {
            crate::log::logger::log_critical(&format!(
                "AHCI: Erasure verification FAILED - sector {} not zero",
                lba
            ));
            return Ok(false);
        }
    }

    crate::log::logger::log_critical(&format!(
        "AHCI: Erasure verification PASSED ({} sectors checked)",
        sample_count
    ));
    Ok(true)
}
