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

//! DMA phase. Four grants land in the broker per setup: RX vring,
//! RX buffer pool, TX vring, TX scratch buffer. Each step rolls
//! back every prior grant in reverse on failure so the broker
//! never holds a partial setup.

use nonos_libc::{
    mk_device_release, mk_dma_map, mk_dma_unmap, mk_irq_unbind, mk_mmio_unmap, DmaMapOut,
    IrqBindOut, MmioMapOut,
};

use crate::constants::{RX_BUFFER_LEN, RX_DESC_COUNT, TX_BUFFER_LEN, VQ_REGION_SIZE};

fn rollback_after(
    device_id: u64,
    mmio: &MmioMapOut,
    irq: &IrqBindOut,
    grants: &[u64],
) {
    for &g in grants.iter().rev() {
        let _ = mk_dma_unmap(g);
    }
    let _ = mk_irq_unbind(irq.grant_id);
    let _ = mk_mmio_unmap(mmio.grant_id);
    let _ = mk_device_release(device_id);
}

pub fn map_rx_queue(
    device_id: u64,
    claim_epoch: u64,
    mmio: &MmioMapOut,
    irq: &IrqBindOut,
) -> Result<DmaMapOut, &'static str> {
    let mut out = DmaMapOut { user_va: 0, device_addr: 0, length: 0, grant_id: 0 };
    let r = mk_dma_map(device_id, claim_epoch, VQ_REGION_SIZE as u64, 0, &mut out);
    if r < 0 {
        rollback_after(device_id, mmio, irq, &[]);
        return Err("dma map failed (rx queue)");
    }
    Ok(out)
}

pub fn map_rx_buffers(
    device_id: u64,
    claim_epoch: u64,
    mmio: &MmioMapOut,
    irq: &IrqBindOut,
    rx_q: &DmaMapOut,
) -> Result<DmaMapOut, &'static str> {
    let mut out = DmaMapOut { user_va: 0, device_addr: 0, length: 0, grant_id: 0 };
    let len = (RX_BUFFER_LEN as u64) * (RX_DESC_COUNT as u64);
    let r = mk_dma_map(device_id, claim_epoch, len, 0, &mut out);
    if r < 0 {
        rollback_after(device_id, mmio, irq, &[rx_q.grant_id]);
        return Err("dma map failed (rx buffers)");
    }
    Ok(out)
}

pub fn map_tx_queue(
    device_id: u64,
    claim_epoch: u64,
    mmio: &MmioMapOut,
    irq: &IrqBindOut,
    rx_q: &DmaMapOut,
    rx_b: &DmaMapOut,
) -> Result<DmaMapOut, &'static str> {
    let mut out = DmaMapOut { user_va: 0, device_addr: 0, length: 0, grant_id: 0 };
    let r = mk_dma_map(device_id, claim_epoch, VQ_REGION_SIZE as u64, 0, &mut out);
    if r < 0 {
        rollback_after(device_id, mmio, irq, &[rx_b.grant_id, rx_q.grant_id]);
        return Err("dma map failed (tx queue)");
    }
    Ok(out)
}

pub fn map_tx_buffer(
    device_id: u64,
    claim_epoch: u64,
    mmio: &MmioMapOut,
    irq: &IrqBindOut,
    rx_q: &DmaMapOut,
    rx_b: &DmaMapOut,
    tx_q: &DmaMapOut,
) -> Result<DmaMapOut, &'static str> {
    let mut out = DmaMapOut { user_va: 0, device_addr: 0, length: 0, grant_id: 0 };
    let r = mk_dma_map(device_id, claim_epoch, TX_BUFFER_LEN as u64, 0, &mut out);
    if r < 0 {
        rollback_after(
            device_id,
            mmio,
            irq,
            &[tx_q.grant_id, rx_b.grant_id, rx_q.grant_id],
        );
        return Err("dma map failed (tx buffer)");
    }
    Ok(out)
}
