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

use x86_64::VirtAddr;

use super::super::config::ConfigSpace;
use super::super::constants::*;
use super::super::error::{PciError, Result};
use super::super::types::{MsiMessage, MsixInfo, PciBar};

pub fn configure_msix(
    _config: &ConfigSpace,
    msix: &MsixInfo,
    bars: &[PciBar; 6],
    vector: u16,
    irq_vector: u8,
) -> Result<()> {
    if vector > msix.table_size {
        return Err(PciError::MsixVectorOutOfRange {
            vector,
            max: msix.table_size,
        });
    }

    let bar = &bars[msix.table_bar as usize];
    let table_base = bar.address().ok_or(PciError::MsixTableAccessFailed)?;

    let entry_offset = msix.table_offset + (vector as u32) * MSIX_ENTRY_SIZE;
    let entry_addr = table_base.as_u64() + entry_offset as u64;

    let msg = MsiMessage::for_local_apic(irq_vector);

    // SAFETY: MSI-X table is mapped and aligned
    let entry = VirtAddr::new(entry_addr);
    crate::memory::mmio::mmio_w32(entry, msg.address as u32);
    crate::memory::mmio::mmio_w32(entry + 4u64, (msg.address >> 32) as u32);
    crate::memory::mmio::mmio_w32(entry + 8u64, msg.data);
    crate::memory::mmio::mmio_w32(entry + 12u64, 0);

    Ok(())
}

pub fn configure_msix_single(
    config: &ConfigSpace,
    msix: &MsixInfo,
    bars: &[PciBar; 6],
    irq_vector: u8,
) -> Result<()> {
    configure_msix(config, msix, bars, 0, irq_vector)?;
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
        return Err(PciError::MsixVectorOutOfRange {
            vector,
            max: msix.table_size,
        });
    }

    let bar = &bars[msix.table_bar as usize];
    let table_base = bar.address().ok_or(PciError::MsixTableAccessFailed)?;

    let entry_offset = msix.table_offset + (vector as u32) * MSIX_ENTRY_SIZE;
    let ctrl_addr = table_base.as_u64() + entry_offset as u64 + MSIX_ENTRY_VECTOR_CTRL as u64;

    // SAFETY: MSI-X table is mapped and aligned
    let current = crate::memory::mmio::mmio_r32(VirtAddr::new(ctrl_addr));
    crate::memory::mmio::mmio_w32(VirtAddr::new(ctrl_addr), current | MSIX_ENTRY_MASKED);

    Ok(())
}

pub fn unmask_msix_vector(msix: &MsixInfo, bars: &[PciBar; 6], vector: u16) -> Result<()> {
    if vector > msix.table_size {
        return Err(PciError::MsixVectorOutOfRange {
            vector,
            max: msix.table_size,
        });
    }

    let bar = &bars[msix.table_bar as usize];
    let table_base = bar.address().ok_or(PciError::MsixTableAccessFailed)?;

    let entry_offset = msix.table_offset + (vector as u32) * MSIX_ENTRY_SIZE;
    let ctrl_addr = table_base.as_u64() + entry_offset as u64 + MSIX_ENTRY_VECTOR_CTRL as u64;

    // SAFETY: MSI-X table is mapped and aligned
    let current = crate::memory::mmio::mmio_r32(VirtAddr::new(ctrl_addr));
    crate::memory::mmio::mmio_w32(VirtAddr::new(ctrl_addr), current & !MSIX_ENTRY_MASKED);

    Ok(())
}

pub fn is_msix_vector_pending(msix: &MsixInfo, bars: &[PciBar; 6], vector: u16) -> Result<bool> {
    if vector > msix.table_size {
        return Err(PciError::MsixVectorOutOfRange {
            vector,
            max: msix.table_size,
        });
    }

    let bar = &bars[msix.pba_bar as usize];
    let pba_base = bar.address().ok_or(PciError::MsixTableAccessFailed)?;

    let qword_index = vector / 64;
    let bit_index = vector % 64;

    let pba_addr = pba_base.as_u64() + msix.pba_offset as u64 + (qword_index as u64 * 8);

    // SAFETY: PBA is mapped and aligned
    let low = crate::memory::mmio::mmio_r32(VirtAddr::new(pba_addr)) as u64;
    let high = crate::memory::mmio::mmio_r32(VirtAddr::new(pba_addr + 4)) as u64;
    let pending = (high << 32) | low;

    Ok((pending & (1u64 << bit_index)) != 0)
}
