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

use nonos_libc::{mk_dma_map, DmaMapOut, IrqBindOut, PioGrantOut};

use crate::constants::dma::{RX_BUF_BYTES, TX_BUF_BYTES};

use super::rollback;

const PAGE_MASK: u64 = 0xFFF;

fn page_round(n: u64) -> u64 {
    (n + PAGE_MASK) & !PAGE_MASK
}

fn alloc(device_id: u64, epoch: u64, bytes: u64) -> Option<DmaMapOut> {
    let mut out = DmaMapOut { user_va: 0, device_addr: 0, length: 0, grant_id: 0 };
    let r = mk_dma_map(device_id, epoch, page_round(bytes), 0, &mut out);
    if r < 0 {
        None
    } else {
        Some(out)
    }
}

pub fn map_all(
    device_id: u64,
    epoch: u64,
    pio: &PioGrantOut,
    irq: &IrqBindOut,
) -> Result<(DmaMapOut, DmaMapOut), &'static str> {
    let rx = alloc(device_id, epoch, RX_BUF_BYTES as u64).ok_or_else(|| {
        rollback::after_irq(device_id, pio, irq, &[]);
        "rx dma failed"
    })?;
    let tx = alloc(device_id, epoch, TX_BUF_BYTES as u64).ok_or_else(|| {
        rollback::after_irq(device_id, pio, irq, &[rx.grant_id]);
        "tx dma failed"
    })?;
    if rx.device_addr > u32::MAX as u64 || tx.device_addr > u32::MAX as u64 {
        rollback::after_irq(device_id, pio, irq, &[tx.grant_id, rx.grant_id]);
        return Err("rtl8139 requires 32-bit dma");
    }
    Ok((rx, tx))
}
