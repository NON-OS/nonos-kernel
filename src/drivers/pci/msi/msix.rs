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

use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::mmio::{map_device_memory, unmap_mmio};

use super::super::config::ConfigSpace;
use super::super::constants::*;
use super::super::error::{PciError, Result};
use super::super::types::{MsiMessage, MsixInfo, PciBar};

fn map_msix_window(table_base: PhysAddr, offset: u64, len: usize) -> Result<VirtAddr> {
    let pa = PhysAddr::new(table_base.as_u64() + offset);
    map_device_memory(pa, len).map_err(|_| PciError::MsixTableAccessFailed)
}

pub fn configure_msix(
    _config: &ConfigSpace,
    msix: &MsixInfo,
    bars: &[PciBar; 6],
    vector: u16,
    irq_vector: u8,
    dest_apic_id: u8,
) -> Result<()> {
    if vector > msix.table_size {
        return Err(PciError::MsixVectorOutOfRange { vector, max: msix.table_size });
    }

    let bar = &bars[msix.table_bar as usize];
    let table_base = bar.address().ok_or(PciError::MsixTableAccessFailed)?;

    let entry_offset = msix.table_offset + (vector as u32) * MSIX_ENTRY_SIZE;
    let entry = map_msix_window(table_base, entry_offset as u64, MSIX_ENTRY_SIZE as usize)?;

    let msg = MsiMessage::for_local_apic(irq_vector, dest_apic_id);

    crate::memory::mmio::mmio_w32(entry, msg.address as u32);
    crate::memory::mmio::mmio_w32(entry + 4u64, (msg.address >> 32) as u32);
    crate::memory::mmio::mmio_w32(entry + 8u64, msg.data);
    crate::memory::mmio::mmio_w32(entry + 12u64, 0);
    let _ = unmap_mmio(entry);

    Ok(())
}

pub fn configure_msix_single(
    config: &ConfigSpace,
    msix: &MsixInfo,
    bars: &[PciBar; 6],
    irq_vector: u8,
    dest_apic_id: u8,
) -> Result<()> {
    configure_msix(config, msix, bars, 0, irq_vector, dest_apic_id)?;
    enable_msix(config, msix)?;
    Ok(())
}

pub fn enable_msix(config: &ConfigSpace, msix: &MsixInfo) -> Result<()> {
    let offset = msix.offset as u16;
    let mut ctrl = config.read16(offset + 2)?;
    ctrl |= MSIX_CTRL_ENABLE;
    ctrl &= !MSIX_CTRL_FUNCTION_MASK;
    config.write16(offset + 2, ctrl)?;
    Ok(())
}

pub fn disable_msix(config: &ConfigSpace, msix: &MsixInfo) -> Result<()> {
    let offset = msix.offset as u16;
    let mut ctrl = config.read16(offset + 2)?;
    ctrl &= !MSIX_CTRL_ENABLE;
    config.write16(offset + 2, ctrl)?;
    Ok(())
}

pub fn is_msix_enabled(config: &ConfigSpace, msix: &MsixInfo) -> Result<bool> {
    let offset = msix.offset as u16;
    let ctrl = config.read16(offset + 2)?;
    Ok((ctrl & MSIX_CTRL_ENABLE) != 0)
}

pub fn mask_all_msix(config: &ConfigSpace, msix: &MsixInfo) -> Result<()> {
    let offset = msix.offset as u16;
    let mut ctrl = config.read16(offset + 2)?;
    ctrl |= MSIX_CTRL_FUNCTION_MASK;
    config.write16(offset + 2, ctrl)?;
    Ok(())
}

pub fn unmask_all_msix(config: &ConfigSpace, msix: &MsixInfo) -> Result<()> {
    let offset = msix.offset as u16;
    let mut ctrl = config.read16(offset + 2)?;
    ctrl &= !MSIX_CTRL_FUNCTION_MASK;
    config.write16(offset + 2, ctrl)?;
    Ok(())
}

pub fn mask_msix_vector(msix: &MsixInfo, bars: &[PciBar; 6], vector: u16) -> Result<()> {
    if vector > msix.table_size {
        return Err(PciError::MsixVectorOutOfRange { vector, max: msix.table_size });
    }

    let bar = &bars[msix.table_bar as usize];
    let table_base = bar.address().ok_or(PciError::MsixTableAccessFailed)?;

    let entry_offset = msix.table_offset + (vector as u32) * MSIX_ENTRY_SIZE;
    let ctrl_offset = entry_offset as u64 + MSIX_ENTRY_VECTOR_CTRL as u64;
    let ctrl = map_msix_window(table_base, ctrl_offset, 4)?;

    let current = crate::memory::mmio::mmio_r32(ctrl);
    crate::memory::mmio::mmio_w32(ctrl, current | MSIX_ENTRY_MASKED);
    let _ = unmap_mmio(ctrl);

    Ok(())
}

pub fn unmask_msix_vector(msix: &MsixInfo, bars: &[PciBar; 6], vector: u16) -> Result<()> {
    if vector > msix.table_size {
        return Err(PciError::MsixVectorOutOfRange { vector, max: msix.table_size });
    }

    let bar = &bars[msix.table_bar as usize];
    let table_base = bar.address().ok_or(PciError::MsixTableAccessFailed)?;

    let entry_offset = msix.table_offset + (vector as u32) * MSIX_ENTRY_SIZE;
    let ctrl_offset = entry_offset as u64 + MSIX_ENTRY_VECTOR_CTRL as u64;
    let ctrl = map_msix_window(table_base, ctrl_offset, 4)?;

    let current = crate::memory::mmio::mmio_r32(ctrl);
    crate::memory::mmio::mmio_w32(ctrl, current & !MSIX_ENTRY_MASKED);
    let _ = unmap_mmio(ctrl);

    Ok(())
}

pub fn is_msix_vector_pending(msix: &MsixInfo, bars: &[PciBar; 6], vector: u16) -> Result<bool> {
    if vector > msix.table_size {
        return Err(PciError::MsixVectorOutOfRange { vector, max: msix.table_size });
    }

    let bar = &bars[msix.pba_bar as usize];
    let pba_base = bar.address().ok_or(PciError::MsixTableAccessFailed)?;

    let qword_index = vector / 64;
    let bit_index = vector % 64;

    let pba_offset = msix.pba_offset as u64 + (qword_index as u64 * 8);
    let pba = map_msix_window(pba_base, pba_offset, 8)?;

    let low = crate::memory::mmio::mmio_r32(pba) as u64;
    let high = crate::memory::mmio::mmio_r32(pba + 4u64) as u64;
    let pending = (high << 32) | low;
    let _ = unmap_mmio(pba);

    Ok((pending & (1u64 << bit_index)) != 0)
}
