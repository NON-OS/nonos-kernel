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
//! LBA and DMA buffer validation.

use alloc::format;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;
use alloc::collections::BTreeMap;
use crate::memory::layout::{KERNEL_BASE, MMIO_BASE, MMIO_SIZE};
use super::super::error::AhciError;
use super::super::types::AhciDevice;

/// Validates that an LBA range doesn't exceed device capacity.
pub fn validate_lba_range(
    ports: &RwLock<BTreeMap<u32, AhciDevice>>,
    validation_failures: &AtomicU64,
    port: u32,
    lba: u64,
    count: u64,
) -> Result<(), AhciError> {
    let ports_guard = ports.read();
    let device = ports_guard.get(&port).ok_or(AhciError::PortNotInitialized)?;

    // Check for overflow
    let end_lba = lba.checked_add(count).ok_or(AhciError::LbaOverflow)?;

    // Check against device capacity
    if end_lba > device.sectors {
        validation_failures.fetch_add(1, Ordering::Relaxed);
        crate::log::logger::log_critical(&format!(
            "AHCI: LBA range validation failed - LBA {} + count {} exceeds device capacity {}",
            lba, count, device.sectors
        ));
        return Err(AhciError::LbaRangeExceeded);
    }

    Ok(())
}

/// Validates that a DMA buffer is in a safe memory region.
pub fn validate_dma_buffer(
    validation_failures: &AtomicU64,
    buffer: u64,
    size: usize,
) -> Result<(), AhciError> {
    if size == 0 {
        return Err(AhciError::InvalidBufferSize);
    }

    // Check for overflow
    let _buffer_end = buffer.checked_add(size as u64)
        .ok_or(AhciError::BufferAddressOverflow)?;

    // Ensure buffer doesn't overlap with kernel critical regions
    let is_kernel_text = buffer >= KERNEL_BASE && buffer < KERNEL_BASE + 0x0200_0000;
    let is_mmio = buffer >= MMIO_BASE && buffer < MMIO_BASE + MMIO_SIZE;

    if is_kernel_text || is_mmio {
        validation_failures.fetch_add(1, Ordering::Relaxed);
        crate::log::logger::log_critical(&format!(
            "AHCI: DMA buffer validation failed - buffer 0x{:x} overlaps kernel critical region",
            buffer
        ));
        return Err(AhciError::BufferInCriticalRegion);
    }

    // Ensure buffer is properly aligned (at least 2-byte aligned for word transfers)
    if buffer % 2 != 0 {
        validation_failures.fetch_add(1, Ordering::Relaxed);
        return Err(AhciError::BufferNotAligned);
    }

    Ok(())
}
