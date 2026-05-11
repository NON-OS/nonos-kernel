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

//! DMA phase. Four grants land in the broker per setup: RX ring,
//! RX buffer pool, TX ring, TX buffer pool. Each step rolls back
//! every prior grant in reverse on failure so the broker never
//! holds a partial setup.

use nonos_libc::{mk_dma_map, DmaMapOut, IrqBindOut, MmioMapOut};

use crate::constants::queue::{RX_BUFFER_POOL_BYTES, RX_RING_BYTES, TX_BUFFER_POOL_BYTES,
    TX_RING_BYTES};

use super::rollback;

const PAGE_MASK: u64 = 0xFFF;

#[inline]
fn page_round(n: u64) -> u64 {
    (n + PAGE_MASK) & !PAGE_MASK
}

fn alloc(device_id: u64, claim_epoch: u64, bytes: u64) -> Option<DmaMapOut> {
    let mut out = DmaMapOut { user_va: 0, device_addr: 0, length: 0, grant_id: 0 };
    let r = mk_dma_map(device_id, claim_epoch, page_round(bytes), 0, &mut out);
    if r < 0 { None } else { Some(out) }
}

pub fn map_rings_and_buffers(
    device_id: u64,
    claim_epoch: u64,
    mmio: &MmioMapOut,
    irq: &IrqBindOut,
) -> Result<(DmaMapOut, DmaMapOut, DmaMapOut, DmaMapOut), &'static str> {
    let rx_ring = alloc(device_id, claim_epoch, RX_RING_BYTES as u64)
        .ok_or_else(|| { rollback::after(device_id, mmio, irq, &[]); "dma map failed (rx ring)" })?;
    let rx_buf = alloc(device_id, claim_epoch, RX_BUFFER_POOL_BYTES as u64).ok_or_else(|| {
        rollback::after(device_id, mmio, irq, &[rx_ring.grant_id]);
        "dma map failed (rx buffers)"
    })?;
    let tx_ring = alloc(device_id, claim_epoch, TX_RING_BYTES as u64).ok_or_else(|| {
        rollback::after(device_id, mmio, irq, &[rx_buf.grant_id, rx_ring.grant_id]);
        "dma map failed (tx ring)"
    })?;
    let tx_buf = alloc(device_id, claim_epoch, TX_BUFFER_POOL_BYTES as u64).ok_or_else(|| {
        rollback::after(device_id, mmio, irq,
            &[tx_ring.grant_id, rx_buf.grant_id, rx_ring.grant_id]);
        "dma map failed (tx buffers)"
    })?;
    Ok((rx_ring, rx_buf, tx_ring, tx_buf))
}
