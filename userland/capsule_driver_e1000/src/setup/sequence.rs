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

//! End-to-end broker handshake: discover -> claim -> MMIO -> IRQ
//! -> RX ring DMA -> RX buffer DMA -> TX ring DMA -> TX buffer
//! DMA. Returns a `Driver` with all grants taken and ring states
//! initialised; the hardware bring-up step in `init` programs the
//! device against those rings.

use crate::constants::MAC_LEN;
use crate::discover::find_e1000;
use crate::queue::{RxRing, TxRing};
use crate::regs::Regs;

use super::driver::Driver;
use super::{claim, dma, irq, mmio};

pub fn run() -> Result<Driver, &'static str> {
    let dev = find_e1000().ok_or("no e1000 device")?;
    let claim_epoch = claim::claim(dev.device_id)?;
    let mmio_grant = mmio::map(dev, claim_epoch)?;
    let irq_grant = irq::bind(dev, claim_epoch, &mmio_grant)?;
    let (rx_ring, rx_buf, tx_ring, tx_buf) =
        dma::map_rings_and_buffers(dev.device_id, claim_epoch, &mmio_grant, &irq_grant)?;
    Ok(Driver {
        device_id: dev.device_id,
        mmio_grant: mmio_grant.grant_id,
        irq_grant: irq_grant.grant_id,
        rx_ring_grant: rx_ring.grant_id,
        rx_buffer_grant: rx_buf.grant_id,
        tx_ring_grant: tx_ring.grant_id,
        tx_buffer_grant: tx_buf.grant_id,
        rx_ring_device_addr: rx_ring.device_addr,
        tx_ring_device_addr: tx_ring.device_addr,
        regs: Regs::new(mmio_grant.user_va),
        mac: [0u8; MAC_LEN],
        rx: RxRing::new(rx_ring.user_va, rx_buf.user_va, rx_buf.device_addr),
        tx: TxRing::new(tx_ring.user_va, tx_buf.user_va, tx_buf.device_addr),
    })
}
