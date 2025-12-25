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
//! AHCI command building functions.

use spin::Mutex;
use alloc::collections::BTreeMap;
use x86_64::PhysAddr;

use super::super::error::AhciError;
use super::super::types::{CommandHeader, CommandTable};
use super::super::dma::PortDma;
use super::super::constants::*;
use super::helpers::{hdr_flags_for, fill_h2d_fis};

/// Setup a command slot for execution.
pub fn setup_slot(
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    port: u32,
    slot: u32,
) -> Result<(*mut CommandHeader, *mut CommandTable, PhysAddr), AhciError> {
    let pdma = port_dma.lock();
    let pdma = pdma.get(&port).ok_or(AhciError::PortDmaNotInitialized)?;

    // SAFETY: cl_entries.0 points to a valid array of 32 CommandHeaders
    let ch = unsafe { pdma.cl_entries.0.add(slot as usize) };
    let (ct_ptr, ct_pa) = pdma.ct_for_slot(slot);
    Ok((ch, ct_ptr, ct_pa))
}

/// Build IDENTIFY DEVICE command.
pub fn build_identify_command(
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    port: u32,
    slot: u32,
    buffer_pa: PhysAddr,
) -> Result<(), AhciError> {
    let (ch, ct_ptr, ct_pa) = setup_slot(port_dma, port, slot)?;
    // SAFETY: ch and ct_ptr point to valid DMA memory
    unsafe {
        core::ptr::write_bytes(ch, 0, 1);
        core::ptr::write_bytes(ct_ptr, 0, 1);

        (*ct_ptr).cfis.fill(0);
        fill_h2d_fis(&mut (*ct_ptr).cfis, ATA_CMD_IDENTIFY, 0, 0, false);

        (*ct_ptr).prdt[0].dba = (buffer_pa.as_u64() & 0xFFFF_FFFF) as u32;
        (*ct_ptr).prdt[0].dbau = (buffer_pa.as_u64() >> 32) as u32;
        (*ct_ptr).prdt[0].reserved0 = 0;
        (*ct_ptr).prdt[0].dbc = (512 - 1) as u32 | (1 << 31);

        (*ch).flags = hdr_flags_for(5, false);
        (*ch).prdtl = 1;
        (*ch).prdbc = 0;
        (*ch).ctba = (ct_pa.as_u64() & 0xFFFF_FFFF) as u32;
        (*ch).ctbau = (ct_pa.as_u64() >> 32) as u32;
    }
    Ok(())
}

/// Build READ DMA EXT command.
pub fn build_read_command(
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    port: u32,
    slot: u32,
    lba: u64,
    count: u16,
    buffer_pa: PhysAddr,
) -> Result<(), AhciError> {
    let (ch, ct_ptr, ct_pa) = setup_slot(port_dma, port, slot)?;
    let bytes = (count as usize) * 512;

    // SAFETY: ch and ct_ptr point to valid DMA memory
    unsafe {
        core::ptr::write_bytes(ch, 0, 1);
        core::ptr::write_bytes(ct_ptr, 0, 1);

        fill_h2d_fis(&mut (*ct_ptr).cfis, ATA_CMD_READ_DMA_EXT, lba, count, false);

        (*ct_ptr).prdt[0].dba = (buffer_pa.as_u64() & 0xFFFF_FFFF) as u32;
        (*ct_ptr).prdt[0].dbau = (buffer_pa.as_u64() >> 32) as u32;
        (*ct_ptr).prdt[0].reserved0 = 0;
        (*ct_ptr).prdt[0].dbc = (bytes as u32 - 1) | (1 << 31);

        (*ch).flags = hdr_flags_for(5, false);
        (*ch).prdtl = 1;
        (*ch).prdbc = 0;
        (*ch).ctba = (ct_pa.as_u64() & 0xFFFF_FFFF) as u32;
        (*ch).ctbau = (ct_pa.as_u64() >> 32) as u32;
    }
    Ok(())
}

/// Build WRITE DMA EXT command.
pub fn build_write_command(
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    port: u32,
    slot: u32,
    lba: u64,
    count: u16,
    buffer_pa: PhysAddr,
) -> Result<(), AhciError> {
    let (ch, ct_ptr, ct_pa) = setup_slot(port_dma, port, slot)?;
    let bytes = (count as usize) * 512;

    // SAFETY: ch and ct_ptr point to valid DMA memory
    unsafe {
        core::ptr::write_bytes(ch, 0, 1);
        core::ptr::write_bytes(ct_ptr, 0, 1);

        fill_h2d_fis(&mut (*ct_ptr).cfis, ATA_CMD_WRITE_DMA_EXT, lba, count, true);

        (*ct_ptr).prdt[0].dba = (buffer_pa.as_u64() & 0xFFFF_FFFF) as u32;
        (*ct_ptr).prdt[0].dbau = (buffer_pa.as_u64() >> 32) as u32;
        (*ct_ptr).prdt[0].reserved0 = 0;
        (*ct_ptr).prdt[0].dbc = (bytes as u32 - 1) | (1 << 31);

        (*ch).flags = hdr_flags_for(5, true);
        (*ch).prdtl = 1;
        (*ch).prdbc = 0;
        (*ch).ctba = (ct_pa.as_u64() & 0xFFFF_FFFF) as u32;
        (*ch).ctbau = (ct_pa.as_u64() >> 32) as u32;
    }
    Ok(())
}

/// Build DSM/TRIM command.
pub fn build_trim_command(
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    port: u32,
    slot: u32,
    buffer_pa: PhysAddr,
    blocks: u16,
) -> Result<(), AhciError> {
    let (ch, ct_ptr, ct_pa) = setup_slot(port_dma, port, slot)?;
    let bytes = (blocks as usize) * 512;

    // SAFETY: ch and ct_ptr point to valid DMA memory
    unsafe {
        core::ptr::write_bytes(ch, 0, 1);
        core::ptr::write_bytes(ct_ptr, 0, 1);

        (*ct_ptr).cfis.fill(0);
        (*ct_ptr).cfis[0] = FIS_TYPE_REG_H2D;
        (*ct_ptr).cfis[1] = 1 << 7;
        (*ct_ptr).cfis[2] = ATA_CMD_DSM;
        (*ct_ptr).cfis[3] = DSM_TRIM;
        (*ct_ptr).cfis[7] = 0x40;
        (*ct_ptr).cfis[12] = (blocks & 0xFF) as u8;
        (*ct_ptr).cfis[13] = (blocks >> 8) as u8;

        (*ct_ptr).prdt[0].dba = (buffer_pa.as_u64() & 0xFFFF_FFFF) as u32;
        (*ct_ptr).prdt[0].dbau = (buffer_pa.as_u64() >> 32) as u32;
        (*ct_ptr).prdt[0].reserved0 = 0;
        (*ct_ptr).prdt[0].dbc = (bytes as u32 - 1) | (1 << 31);

        (*ch).flags = hdr_flags_for(5, true);
        (*ch).prdtl = 1;
        (*ch).prdbc = 0;
        (*ch).ctba = (ct_pa.as_u64() & 0xFFFF_FFFF) as u32;
        (*ch).ctbau = (ct_pa.as_u64() >> 32) as u32;
    }
    Ok(())
}

/// Build SECURITY ERASE PREPARE command.
pub fn build_security_erase_prepare_command(
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    port: u32,
    slot: u32,
) -> Result<(), AhciError> {
    let (ch, ct_ptr, ct_pa) = setup_slot(port_dma, port, slot)?;
    // SAFETY: ch and ct_ptr point to valid DMA memory
    unsafe {
        core::ptr::write_bytes(ch, 0, 1);
        core::ptr::write_bytes(ct_ptr, 0, 1);

        (*ct_ptr).cfis.fill(0);
        (*ct_ptr).cfis[0] = FIS_TYPE_REG_H2D;
        (*ct_ptr).cfis[1] = 1 << 7;
        (*ct_ptr).cfis[2] = ATA_CMD_SECURITY_ERASE_PREPARE;
        (*ct_ptr).cfis[7] = 0x40;

        (*ch).flags = hdr_flags_for(5, false);
        (*ch).prdtl = 0;
        (*ch).prdbc = 0;
        (*ch).ctba = (ct_pa.as_u64() & 0xFFFF_FFFF) as u32;
        (*ch).ctbau = (ct_pa.as_u64() >> 32) as u32;
    }
    Ok(())
}

/// Build SECURITY ERASE UNIT command.
pub fn build_security_erase_unit_command(
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    port: u32,
    slot: u32,
    enhanced: bool,
) -> Result<(), AhciError> {
    let (ch, ct_ptr, ct_pa) = setup_slot(port_dma, port, slot)?;
    // SAFETY: ch and ct_ptr point to valid DMA memory
    unsafe {
        core::ptr::write_bytes(ch, 0, 1);
        core::ptr::write_bytes(ct_ptr, 0, 1);

        (*ct_ptr).cfis.fill(0);
        (*ct_ptr).cfis[0] = FIS_TYPE_REG_H2D;
        (*ct_ptr).cfis[1] = 1 << 7;
        (*ct_ptr).cfis[2] = ATA_CMD_SECURITY_ERASE_UNIT;
        (*ct_ptr).cfis[3] = if enhanced { 0x02 } else { 0x00 };
        (*ct_ptr).cfis[7] = 0x40;

        (*ch).flags = hdr_flags_for(5, false);
        (*ch).prdtl = 0;
        (*ch).prdbc = 0;
        (*ch).ctba = (ct_pa.as_u64() & 0xFFFF_FFFF) as u32;
        (*ch).ctbau = (ct_pa.as_u64() >> 32) as u32;
    }
    Ok(())
}
