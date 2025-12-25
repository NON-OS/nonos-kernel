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
//! AHCI I/O operations (read, write, TRIM).

use alloc::collections::BTreeMap;
use spin::{Mutex, RwLock};
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use x86_64::PhysAddr;

use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};
use crate::crypto::aes::Aes256;

use super::super::error::AhciError;
use super::super::types::AhciDevice;
use super::super::dma::PortDma;
use super::super::constants::*;
use super::{commands, encryption, validation};
use super::helpers::RegisterAccess;

/// Read sectors implementation.
pub fn read_sectors<T: RegisterAccess>(
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
    lba: u64,
    count: u16,
    buffer_va: u64,
) -> Result<(), AhciError> {
    if !ports.read().contains_key(&port) {
        return Err(AhciError::PortNotInitialized);
    }

    validation::validate_lba_range(ports, validation_failures, port, lba, count as u64)?;
    validation::validate_dma_buffer(validation_failures, buffer_va, (count as usize) * 512)?;

    let slot = find_free_slot(ctrl, port)?;
    commands::build_read_command(port_dma, port, slot, lba, count, PhysAddr::new(buffer_va))?;

    ctrl.write_port_reg(port, PORT_CI, 1 << slot);
    wait_complete_or_error(ctrl, errors, port_resets, command_timeout, port, slot)?;

    read_ops.fetch_add(1, Ordering::Relaxed);
    bytes_read.fetch_add((count as u64) * 512, Ordering::Relaxed);

    if encryption_enabled.load(Ordering::Relaxed) {
        encryption::decrypt_buffer_aes(aes_cipher, encryption_iv, buffer_va, (count as usize) * 512, lba)?;
    }
    Ok(())
}

/// Write sectors implementation.
pub fn write_sectors<T: RegisterAccess>(
    ctrl: &T,
    ports: &RwLock<BTreeMap<u32, AhciDevice>>,
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    validation_failures: &AtomicU64,
    write_ops: &AtomicU64,
    bytes_written: &AtomicU64,
    errors: &AtomicU64,
    port_resets: &AtomicU64,
    encryption_enabled: &AtomicBool,
    aes_cipher: &Mutex<Option<Aes256>>,
    encryption_iv: &[u8; 16],
    command_timeout: u32,
    port: u32,
    lba: u64,
    count: u16,
    buffer_va: u64,
) -> Result<(), AhciError> {
    if !ports.read().contains_key(&port) {
        return Err(AhciError::PortNotInitialized);
    }

    validation::validate_lba_range(ports, validation_failures, port, lba, count as u64)?;
    validation::validate_dma_buffer(validation_failures, buffer_va, (count as usize) * 512)?;

    if encryption_enabled.load(Ordering::Relaxed) {
        encryption::encrypt_buffer_aes(aes_cipher, encryption_iv, buffer_va, (count as usize) * 512, lba)?;
    }

    let slot = find_free_slot(ctrl, port)?;
    commands::build_write_command(port_dma, port, slot, lba, count, PhysAddr::new(buffer_va))?;

    ctrl.write_port_reg(port, PORT_CI, 1 << slot);
    wait_complete_or_error(ctrl, errors, port_resets, command_timeout, port, slot)?;

    write_ops.fetch_add(1, Ordering::Relaxed);
    bytes_written.fetch_add((count as u64) * 512, Ordering::Relaxed);
    Ok(())
}

/// TRIM sectors with rate limiting.
pub fn trim_sectors<T: RegisterAccess>(
    ctrl: &T,
    ports: &RwLock<BTreeMap<u32, AhciDevice>>,
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    validation_failures: &AtomicU64,
    trim_ops: &AtomicU64,
    errors: &AtomicU64,
    port_resets: &AtomicU64,
    command_timeout: u32,
    port: u32,
    lba: u64,
    count: u32,
) -> Result<(), AhciError> {
    let devs = ports.read();
    let dev = devs.get(&port).ok_or(AhciError::PortNotInitialized)?;
    if !dev.supports_trim {
        return Err(AhciError::TrimNotSupported);
    }

    let now = ctrl.get_timestamp_us();
    let last_trim = dev.last_trim_timestamp.load(Ordering::Relaxed);
    if now < last_trim + TRIM_RATE_LIMIT_INTERVAL_US {
        return Err(AhciError::TrimRateLimitExceeded);
    }
    dev.last_trim_timestamp.store(now, Ordering::Relaxed);
    drop(devs);

    if count == 0 {
        return Ok(());
    }

    validation::validate_lba_range(ports, validation_failures, port, lba, count as u64)?;

    let mut remaining = count as u64;
    let mut current_lba = lba;
    let total_desc = ((remaining + 0xFFFF - 1) / 0xFFFF) as usize;
    let blocks = ((total_desc + 63) / 64) as usize;
    let total_bytes = blocks * 512;

    let buf_dma_region = alloc_dma_coherent(total_bytes, DmaConstraints {
        alignment: 2,
        max_segment_size: total_bytes,
        dma32_only: false,
        coherent: true,
    }).map_err(|_| AhciError::DmaAllocationFailed)?;

    let (buf_va, buf_pa) = (buf_dma_region.virt_addr, buf_dma_region.phys_addr);
    unsafe { core::ptr::write_bytes(buf_va.as_mut_ptr::<u8>(), 0, total_bytes); }

    // Fill TRIM descriptors
    let mut desc_written = 0usize;
    let mut ptr_u8 = buf_va.as_mut_ptr::<u8>();
    for _ in 0..blocks {
        let block_desc = core::cmp::min(64, total_desc - desc_written);
        for _ in 0..block_desc {
            let this_count = core::cmp::min(remaining, 0xFFFF);
            unsafe {
                core::ptr::write(ptr_u8, (current_lba & 0xFF) as u8);
                core::ptr::write(ptr_u8.add(1), ((current_lba >> 8) & 0xFF) as u8);
                core::ptr::write(ptr_u8.add(2), ((current_lba >> 16) & 0xFF) as u8);
                core::ptr::write(ptr_u8.add(3), ((current_lba >> 24) & 0xFF) as u8);
                core::ptr::write(ptr_u8.add(4), ((current_lba >> 32) & 0xFF) as u8);
                core::ptr::write(ptr_u8.add(5), ((current_lba >> 40) & 0xFF) as u8);
                let sc = this_count as u16;
                core::ptr::write(ptr_u8.add(6), (sc & 0xFF) as u8);
                core::ptr::write(ptr_u8.add(7), (sc >> 8) as u8);
            }
            current_lba = current_lba.checked_add(this_count).ok_or(AhciError::LbaOverflow)?;
            remaining -= this_count;
            desc_written += 1;
            unsafe { ptr_u8 = ptr_u8.add(8); }
            if remaining == 0 { break; }
        }
    }

    let slot = find_free_slot(ctrl, port)?;
    commands::build_trim_command(port_dma, port, slot, buf_pa, blocks as u16)?;
    ctrl.write_port_reg(port, PORT_CI, 1 << slot);
    wait_complete_or_error(ctrl, errors, port_resets, command_timeout, port, slot)?;

    trim_ops.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Find a free command slot.
pub fn find_free_slot<T: RegisterAccess>(ctrl: &T, port: u32) -> Result<u32, AhciError> {
    let slots = ctrl.read_port_reg(port, PORT_SACT) | ctrl.read_port_reg(port, PORT_CI);
    for slot in 0..32 {
        if (slots & (1 << slot)) == 0 {
            return Ok(slot);
        }
    }
    Err(AhciError::NoFreeSlots)
}

/// Wait for command completion or error.
pub fn wait_complete_or_error<T: RegisterAccess>(
    ctrl: &T,
    errors: &AtomicU64,
    port_resets: &AtomicU64,
    timeout: u32,
    port: u32,
    slot: u32,
) -> Result<(), AhciError> {
    let mut remaining = timeout;

    loop {
        let ci = ctrl.read_port_reg(port, PORT_CI);
        let is = ctrl.read_port_reg(port, PORT_IS);
        let tfd = ctrl.read_port_reg(port, PORT_TFD);

        if (ci & (1 << slot)) == 0 {
            ctrl.write_port_reg(port, PORT_IS, is);
            if (is & IS_TFES) != 0 || (tfd & 0x01) != 0 {
                errors.fetch_add(1, Ordering::Relaxed);
                let _ = reset_port_on_error(ctrl, port_resets, port);
                return Err(AhciError::CommandFailed);
            }
            return Ok(());
        }

        if (is & IS_TFES) != 0 {
            ctrl.write_port_reg(port, PORT_IS, is);
            errors.fetch_add(1, Ordering::Relaxed);
            let _ = reset_port_on_error(ctrl, port_resets, port);
            return Err(AhciError::CommandFailed);
        }

        if remaining == 0 {
            errors.fetch_add(1, Ordering::Relaxed);
            let _ = reset_port_on_error(ctrl, port_resets, port);
            return Err(AhciError::CommandTimeout);
        }
        remaining -= 1;
    }
}

/// Reset port on error.
pub fn reset_port_on_error<T: RegisterAccess>(
    ctrl: &T,
    port_resets: &AtomicU64,
    port: u32,
) -> Result<(), AhciError> {
    port_resets.fetch_add(1, Ordering::Relaxed);

    let mut cmd = ctrl.read_port_reg(port, PORT_CMD) & !(CMD_ST | CMD_FRE);
    ctrl.write_port_reg(port, PORT_CMD, cmd);

    if !ctrl.wait_while(|| (ctrl.read_port_reg(port, PORT_CMD) & (CMD_CR | CMD_FR)) != 0, PORT_RESET_TIMEOUT) {
        return Err(AhciError::PortResetFailed);
    }

    ctrl.write_port_reg(port, PORT_SERR, 0xFFFF_FFFF);
    ctrl.write_port_reg(port, PORT_IS, 0xFFFF_FFFF);

    cmd = ctrl.read_port_reg(port, PORT_CMD) | CMD_FRE | CMD_ST;
    ctrl.write_port_reg(port, PORT_CMD, cmd);
    Ok(())
}
