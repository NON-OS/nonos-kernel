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

//! DMA phase. Three grants: queue (descriptors + avail/used rings),
//! header (request header + trailing status byte), and data
//! (read/write payload bounded by `MAX_SECTORS_PER_REQUEST`). Each
//! step rolls back every prior grant in reverse so the broker
//! never holds a partial setup.

use nonos_libc::{mk_device_release, mk_dma_map, mk_dma_unmap, mk_irq_unbind, DmaMapOut, IrqBindOut};

use crate::constants::{DATA_BUF_LEN, HEADER_BUF_LEN, VQ_REGION_SIZE};
use super::registers::RegisterGrant;

pub fn map_queue(
    device_id: u64,
    claim_epoch: u64,
    regs: RegisterGrant,
    irq: &IrqBindOut,
) -> Result<DmaMapOut, &'static str> {
    let mut out = DmaMapOut { user_va: 0, device_addr: 0, length: 0, grant_id: 0 };
    let r = mk_dma_map(device_id, claim_epoch, VQ_REGION_SIZE as u64, 0, &mut out);
    if r < 0 {
        let _ = mk_irq_unbind(irq.grant_id);
        regs.release();
        let _ = mk_device_release(device_id);
        return Err("dma map failed (queue)");
    }
    Ok(out)
}

pub fn map_header(
    device_id: u64,
    claim_epoch: u64,
    regs: RegisterGrant,
    irq: &IrqBindOut,
    queue: &DmaMapOut,
) -> Result<DmaMapOut, &'static str> {
    let mut out = DmaMapOut { user_va: 0, device_addr: 0, length: 0, grant_id: 0 };
    let r = mk_dma_map(device_id, claim_epoch, HEADER_BUF_LEN, 0, &mut out);
    if r < 0 {
        let _ = mk_dma_unmap(queue.grant_id);
        let _ = mk_irq_unbind(irq.grant_id);
        regs.release();
        let _ = mk_device_release(device_id);
        return Err("dma map failed (header)");
    }
    Ok(out)
}

pub fn map_data(
    device_id: u64,
    claim_epoch: u64,
    regs: RegisterGrant,
    irq: &IrqBindOut,
    queue: &DmaMapOut,
    header: &DmaMapOut,
) -> Result<DmaMapOut, &'static str> {
    let mut out = DmaMapOut { user_va: 0, device_addr: 0, length: 0, grant_id: 0 };
    let r = mk_dma_map(device_id, claim_epoch, DATA_BUF_LEN, 0, &mut out);
    if r < 0 {
        let _ = mk_dma_unmap(header.grant_id);
        let _ = mk_dma_unmap(queue.grant_id);
        let _ = mk_irq_unbind(irq.grant_id);
        regs.release();
        let _ = mk_device_release(device_id);
        return Err("dma map failed (data)");
    }
    Ok(out)
}
