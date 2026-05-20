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
use crate::memory::layout::{PAGE_SIZE, PAGE_SIZE_U64};
use crate::memory::mmio::{map_device_memory, unmap_mmio};

use super::super::config::ConfigSpace;
use super::super::constants::*;
use super::super::error::{PciError, Result};
use super::super::types::{MsiMessage, MsixInfo, PciBar};

const PAGE_OFFSET_MASK: u64 = PAGE_SIZE_U64 - 1;

struct MappedMsixWindow {
    base: VirtAddr,
    addr: VirtAddr,
}

impl Drop for MappedMsixWindow {
    fn drop(&mut self) {
        let _ = unmap_mmio(self.base);
    }
}

fn map_msix_window(
    bars: &[PciBar; 6],
    bar_index: u8,
    offset: u64,
    access_len: u64,
) -> Result<MappedMsixWindow> {
    if access_len == 0 {
        return Err(PciError::MsixTableAccessFailed);
    }
    let bar = bars.get(bar_index as usize).ok_or(PciError::MsixTableAccessFailed)?;
    let bar_base = bar.address().ok_or(PciError::MsixTableAccessFailed)?;
    let bar_size = bar.size();
    let end = offset.checked_add(access_len).ok_or(PciError::MsixTableAccessFailed)?;
    if end > bar_size {
        return Err(PciError::MsixTableAccessFailed);
    }
    let phys = bar_base.as_u64().checked_add(offset).ok_or(PciError::MsixTableAccessFailed)?;
    let page_phys = phys & !PAGE_OFFSET_MASK;
    let page_off = phys & PAGE_OFFSET_MASK;
    let map_len = if page_off + access_len > PAGE_SIZE_U64 { PAGE_SIZE * 2 } else { PAGE_SIZE };
    let base = map_device_memory(PhysAddr::new(page_phys), map_len)
        .map_err(|_| PciError::MsixTableAccessFailed)?;
    Ok(MappedMsixWindow { base, addr: base + page_off })
}

fn map_msix_table_entry(
    msix: &MsixInfo,
    bars: &[PciBar; 6],
    vector: u16,
) -> Result<MappedMsixWindow> {
    if vector > msix.table_size {
        return Err(PciError::MsixVectorOutOfRange { vector, max: msix.table_size });
    }
    let entry_offset = (msix.table_offset as u64)
        .checked_add((vector as u64) * (MSIX_ENTRY_SIZE as u64))
        .ok_or(PciError::MsixTableAccessFailed)?;
    map_msix_window(bars, msix.table_bar, entry_offset, MSIX_ENTRY_SIZE as u64)
}

pub fn configure_msix(
    _config: &ConfigSpace,
    msix: &MsixInfo,
    bars: &[PciBar; 6],
    vector: u16,
    irq_vector: u8,
    dest_apic_id: u8,
) -> Result<()> {
    let msg = MsiMessage::for_local_apic(irq_vector, dest_apic_id);
    let entry = map_msix_table_entry(msix, bars, vector)?;

    crate::memory::mmio::mmio_w32(entry.addr, msg.address as u32);
    crate::memory::mmio::mmio_w32(entry.addr + 4u64, (msg.address >> 32) as u32);
    crate::memory::mmio::mmio_w32(entry.addr + 8u64, msg.data);
    crate::memory::mmio::mmio_w32(entry.addr + 12u64, 0);

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
    let entry = map_msix_table_entry(msix, bars, vector)?;
    let ctrl_addr = entry.addr + MSIX_ENTRY_VECTOR_CTRL as u64;

    let current = crate::memory::mmio::mmio_r32(ctrl_addr);
    crate::memory::mmio::mmio_w32(ctrl_addr, current | MSIX_ENTRY_MASKED);

    Ok(())
}

pub fn unmask_msix_vector(msix: &MsixInfo, bars: &[PciBar; 6], vector: u16) -> Result<()> {
    let entry = map_msix_table_entry(msix, bars, vector)?;
    let ctrl_addr = entry.addr + MSIX_ENTRY_VECTOR_CTRL as u64;

    let current = crate::memory::mmio::mmio_r32(ctrl_addr);
    crate::memory::mmio::mmio_w32(ctrl_addr, current & !MSIX_ENTRY_MASKED);

    Ok(())
}

pub fn is_msix_vector_pending(msix: &MsixInfo, bars: &[PciBar; 6], vector: u16) -> Result<bool> {
    if vector > msix.table_size {
        return Err(PciError::MsixVectorOutOfRange { vector, max: msix.table_size });
    }

    let qword_index = vector / 64;
    let bit_index = vector % 64;
    let pba_offset = (msix.pba_offset as u64)
        .checked_add(qword_index as u64 * 8)
        .ok_or(PciError::MsixTableAccessFailed)?;
    let pba = map_msix_window(bars, msix.pba_bar, pba_offset, 8)?;

    let low = crate::memory::mmio::mmio_r32(pba.addr) as u64;
    let high = crate::memory::mmio::mmio_r32(pba.addr + 4u64) as u64;
    let pending = (high << 32) | low;

    Ok((pending & (1u64 << bit_index)) != 0)
}

pub fn zero_msix_vector(msix: &MsixInfo, bars: &[PciBar; 6], vector: u16) -> Result<()> {
    let entry = map_msix_table_entry(msix, bars, vector)?;
    crate::memory::mmio::mmio_w32(entry.addr, 0);
    crate::memory::mmio::mmio_w32(entry.addr + 4u64, 0);
    crate::memory::mmio::mmio_w32(entry.addr + 8u64, 0);
    crate::memory::mmio::mmio_w32(entry.addr + 12u64, MSIX_ENTRY_MASKED);
    Ok(())
}
