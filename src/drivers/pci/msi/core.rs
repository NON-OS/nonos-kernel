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

use super::super::config::ConfigSpace;
use super::super::constants::*;
use super::super::error::{PciError, Result};
use super::super::types::{MsiInfo, MsiMessage};

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
