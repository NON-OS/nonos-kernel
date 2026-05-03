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

use super::super::constants::{PORT_CI, PORT_SACT};
use super::super::dma::PortDma;
use super::super::error::AhciError;
use super::super::types::AhciDevice;
use super::helpers::RegisterAccess;
use super::ncq_wait::wait_ncq_complete;
use super::{encryption, io, ncq, validation};
use crate::crypto::aes::Aes256;
use crate::memory::addr::PhysAddr;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

pub(crate) fn ncq_write_sectors<T: RegisterAccess>(
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
    let supports_ncq = ports.read().get(&port).map(|d| d.supports_ncq).unwrap_or(false);
    if !supports_ncq {
        return io::write_sectors(
            ctrl,
            ports,
            port_dma,
            validation_failures,
            write_ops,
            bytes_written,
            errors,
            port_resets,
            encryption_enabled,
            aes_cipher,
            encryption_iv,
            command_timeout,
            port,
            lba,
            count,
            buffer_va,
        );
    }
    if !ports.read().contains_key(&port) {
        return Err(AhciError::PortNotInitialized);
    }
    validation::validate_lba_range(ports, validation_failures, port, lba, count as u64)?;
    validation::validate_dma_buffer(validation_failures, buffer_va, (count as usize) * 512)?;
    if encryption_enabled.load(Ordering::Relaxed) {
        encryption::encrypt_buffer_aes(
            aes_cipher,
            encryption_iv,
            buffer_va,
            (count as usize) * 512,
            lba,
        )?;
    }
    let tag = io::find_free_slot(ctrl, port)?;
    ncq::build_ncq_write_command(port_dma, port, tag, lba, count, PhysAddr::new(buffer_va))?;
    ctrl.write_port_reg(port, PORT_SACT, 1 << tag);
    ctrl.write_port_reg(port, PORT_CI, 1 << tag);
    wait_ncq_complete(ctrl, errors, port_resets, command_timeout, port, tag)?;
    write_ops.fetch_add(1, Ordering::Relaxed);
    bytes_written.fetch_add((count as u64) * 512, Ordering::Relaxed);
    Ok(())
}
