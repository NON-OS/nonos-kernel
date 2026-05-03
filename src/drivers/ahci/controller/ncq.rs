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

use super::super::dma::PortDma;
use super::super::error::AhciError;
use super::commands::setup_slot;
use super::helpers::hdr_flags_for;
use super::ncq_fis::fill_fpdma_fis;
use crate::memory::addr::PhysAddr;
use alloc::collections::BTreeMap;
use spin::Mutex;

pub(crate) const ATA_CMD_FPDMA_READ: u8 = 0x60;
pub(crate) const ATA_CMD_FPDMA_WRITE: u8 = 0x61;

pub(crate) fn build_ncq_read_command(
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    port: u32,
    tag: u32,
    lba: u64,
    count: u16,
    buffer_pa: PhysAddr,
) -> Result<(), AhciError> {
    let (ch, ct_ptr, ct_pa) = setup_slot(port_dma, port, tag)?;
    let bytes = (count as usize) * 512;
    unsafe {
        core::ptr::write_bytes(ch, 0, 1);
        core::ptr::write_bytes(ct_ptr, 0, 1);
        fill_fpdma_fis(&mut (*ct_ptr).cfis, ATA_CMD_FPDMA_READ, lba, count, tag as u8, false);
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

pub(crate) fn build_ncq_write_command(
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    port: u32,
    tag: u32,
    lba: u64,
    count: u16,
    buffer_pa: PhysAddr,
) -> Result<(), AhciError> {
    let (ch, ct_ptr, ct_pa) = setup_slot(port_dma, port, tag)?;
    let bytes = (count as usize) * 512;
    unsafe {
        core::ptr::write_bytes(ch, 0, 1);
        core::ptr::write_bytes(ct_ptr, 0, 1);
        fill_fpdma_fis(&mut (*ct_ptr).cfis, ATA_CMD_FPDMA_WRITE, lba, count, tag as u8, true);
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
