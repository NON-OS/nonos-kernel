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

use x86_64::VirtAddr;

use super::config::ConfigSpace;
use super::constants::*;
use super::error::{PciError, Result};
use super::types::{MsiInfo, MsiMessage, MsixInfo, PciBar, PciDevice};

pub fn configure_msi(config: &ConfigSpace, msi: &MsiInfo, vector: u8) -> Result<()> {
    configure_msi_multi(config, msi, &[vector])
}

pub fn configure_msi_multi(config: &ConfigSpace, msi: &MsiInfo, vectors: &[u8]) -> Result<()> {
    if vectors.is_empty() {
        return Err(PciError::MsiNotSupported);
    }

    let max_vectors = msi.max_vectors() as usize;
    let requested = vectors.len().min(max_vectors);
    let log2_count = (requested as u32).next_power_of_two().trailing_zeros() as u8;
    let actual_log2 = log2_count.min(msi.multi_message_capable);
    let msg = MsiMessage::for_local_apic(vectors[0]);
    let offset = msi.offset as u16;

    config.write32(offset + 4, msg.address as u32)?;

    let data_offset = if msi.is_64bit {
        config.write32(offset + 8, (msg.address >> 32) as u32)?;
        offset + 12
    } else {
        offset + 8
    };

    config.write16(data_offset, msg.data as u16)?;

    if msi.per_vector_mask && msi.is_64bit {
        let mask_offset = data_offset + 4;
        config.write32(mask_offset, 0)?;
    }

    let mut ctrl = config.read16(offset + 2)?;
    ctrl &= !(MSI_CTRL_MME_MASK);
    ctrl |= (actual_log2 as u16) << 4;
    ctrl |= MSI_CTRL_ENABLE;
    config.write16(offset + 2, ctrl)?;

    Ok(())
}

pub fn disable_msi(config: &ConfigSpace, msi: &MsiInfo) -> Result<()> {
    let offset = msi.offset as u16;
    let mut ctrl = config.read16(offset + 2)?;
    ctrl &= !MSI_CTRL_ENABLE;
    config.write16(offset + 2, ctrl)?;
    Ok(())
}

pub fn is_msi_enabled(config: &ConfigSpace, msi: &MsiInfo) -> Result<bool> {
    let offset = msi.offset as u16;
    let ctrl = config.read16(offset + 2)?;
    Ok((ctrl & MSI_CTRL_ENABLE) != 0)
}

pub fn mask_msi_vector(config: &ConfigSpace, msi: &MsiInfo, vector: u8) -> Result<()> {
    if !msi.per_vector_mask {
        return Err(PciError::MsiNotSupported);
    }

    let mask_offset = if msi.is_64bit {
        msi.offset as u16 + 16
    } else {
        msi.offset as u16 + 12
    };

    let mut mask = config.read32(mask_offset)?;
    mask |= 1u32 << vector;
    config.write32(mask_offset, mask)?;

    Ok(())
}

pub fn unmask_msi_vector(config: &ConfigSpace, msi: &MsiInfo, vector: u8) -> Result<()> {
    if !msi.per_vector_mask {
        return Err(PciError::MsiNotSupported);
    }

    let mask_offset = if msi.is_64bit {
        msi.offset as u16 + 16
    } else {
        msi.offset as u16 + 12
    };

    let mut mask = config.read32(mask_offset)?;
    mask &= !(1u32 << vector);
    config.write32(mask_offset, mask)?;

    Ok(())
}

pub fn configure_msix(
    config: &ConfigSpace,
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
    unsafe {
        let entry = VirtAddr::new(entry_addr);
        crate::memory::mmio::mmio_w32(entry, msg.address as u32);
        crate::memory::mmio::mmio_w32(entry + 4u64, (msg.address >> 32) as u32);
        crate::memory::mmio::mmio_w32(entry + 8u64, msg.data);
        crate::memory::mmio::mmio_w32(entry + 12u64, 0);
    }

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
    unsafe {
        let current = crate::memory::mmio::mmio_r32(VirtAddr::new(ctrl_addr));
        crate::memory::mmio::mmio_w32(VirtAddr::new(ctrl_addr), current | MSIX_ENTRY_MASKED);
    }

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
    unsafe {
        let current = crate::memory::mmio::mmio_r32(VirtAddr::new(ctrl_addr));
        crate::memory::mmio::mmio_w32(VirtAddr::new(ctrl_addr), current & !MSIX_ENTRY_MASKED);
    }

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
    let pending = unsafe {
        let low = crate::memory::mmio::mmio_r32(VirtAddr::new(pba_addr)) as u64;
        let high = crate::memory::mmio::mmio_r32(VirtAddr::new(pba_addr + 4)) as u64;
        (high << 32) | low
    };

    Ok((pending & (1u64 << bit_index)) != 0)
}

pub struct MsiController<'a> {
    config: &'a ConfigSpace,
    msi: Option<MsiInfo>,
    msix: Option<MsixInfo>,
    bars: &'a [PciBar; 6],
}

impl<'a> MsiController<'a> {
    pub fn new(device: &'a PciDevice, config: &'a ConfigSpace) -> Self {
        Self {
            config,
            msi: device.msi,
            msix: device.msix,
            bars: &device.bars,
        }
    }

    pub fn supports_msi(&self) -> bool {
        self.msi.is_some()
    }

    pub fn supports_msix(&self) -> bool {
        self.msix.is_some()
    }

    pub fn configure_single_vector(&self, vector: u8) -> Result<()> {
        if let Some(ref msix) = self.msix {
            configure_msix_single(self.config, msix, self.bars, vector)
        } else if let Some(ref msi) = self.msi {
            configure_msi(self.config, msi, vector)
        } else {
            Err(PciError::MsiNotSupported)
        }
    }

    pub fn disable(&self) -> Result<()> {
        if let Some(ref msix) = self.msix {
            disable_msix(self.config, msix)?;
        }
        if let Some(ref msi) = self.msi {
            disable_msi(self.config, msi)?;
        }
        Ok(())
    }

    pub fn is_enabled(&self) -> Result<bool> {
        if let Some(ref msix) = self.msix {
            if is_msix_enabled(self.config, msix)? {
                return Ok(true);
            }
        }
        if let Some(ref msi) = self.msi {
            if is_msi_enabled(self.config, msi)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn max_vectors(&self) -> u16 {
        if let Some(ref msix) = self.msix {
            return msix.vector_count();
        }
        if let Some(ref msi) = self.msi {
            return msi.max_vectors() as u16;
        }
        0
    }
}

pub fn disable_legacy_interrupt(config: &ConfigSpace) -> Result<()> {
    config.disable_interrupts()
}

pub fn enable_legacy_interrupt(config: &ConfigSpace) -> Result<()> {
    config.enable_interrupts()
}

pub fn get_interrupt_line(config: &ConfigSpace) -> Result<u8> {
    config.interrupt_line()
}

pub fn get_interrupt_pin(config: &ConfigSpace) -> Result<u8> {
    config.interrupt_pin()
}
