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

//! End-to-end setup: discover -> claim -> MMIO -> IRQ ->
//! RX queue / RX buffer / TX queue / TX buffer DMA -> negotiate
//! features -> program both queues -> read MAC -> RX prime ->
//! DRIVER_OK -> first IRQ unmask. Each phase emits a marker;
//! failure inside any phase rolls back through the corresponding
//! helper before this function returns.

use nonos_libc::mk_irq_ack;

use super::driver::Driver;
use super::{claim, dma, irq, mmio};
use crate::constants::{LEG_MAC, MAC_LEN, Q_RX, Q_TX, VIRTIO_NET_F_MAC, VIRTIO_NET_F_STATUS};
use crate::discover::find_virtio_net;
use crate::init::{driver_ok, negotiate, program_queue};
use crate::queue::{RxQueue, TxQueue};
use crate::regs::Regs;

const fn bit(n: u32) -> u32 {
    1u32 << n
}

pub fn run() -> Result<Driver, &'static str> {
    let dev = find_virtio_net().ok_or("no virtio-net device")?;

    let claim_epoch = claim::claim(dev.device_id)?;

    let mmio_grant = mmio::map(dev, claim_epoch)?;

    let irq_grant = irq::bind(dev, claim_epoch, &mmio_grant)?;

    let rx_queue_dma = dma::map_rx_queue(dev.device_id, claim_epoch, &mmio_grant, &irq_grant)?;
    let rx_buf_dma =
        dma::map_rx_buffers(dev.device_id, claim_epoch, &mmio_grant, &irq_grant, &rx_queue_dma)?;
    let tx_queue_dma = dma::map_tx_queue(
        dev.device_id, claim_epoch, &mmio_grant, &irq_grant, &rx_queue_dma, &rx_buf_dma,
    )?;
    let tx_buf_dma = dma::map_tx_buffer(
        dev.device_id, claim_epoch, &mmio_grant, &irq_grant, &rx_queue_dma, &rx_buf_dma,
        &tx_queue_dma,
    )?;

    let regs = Regs::new(mmio_grant.user_va);
    let negotiated = negotiate(regs)?;
    let mac_supported = negotiated & bit(VIRTIO_NET_F_MAC) != 0;
    let status_supported = negotiated & bit(VIRTIO_NET_F_STATUS) != 0;

    let _ = program_queue(regs, Q_RX, rx_queue_dma.device_addr, RxQueue::queue_size())?;
    let _ = program_queue(regs, Q_TX, tx_queue_dma.device_addr, TxQueue::queue_size())?;
    let rx = RxQueue::new(
        rx_queue_dma.user_va, rx_queue_dma.device_addr, rx_buf_dma.user_va, rx_buf_dma.device_addr,
    );
    let tx = TxQueue::new(
        tx_queue_dma.user_va, tx_queue_dma.device_addr, tx_buf_dma.user_va, tx_buf_dma.device_addr,
    );

    let mut mac = [0u8; MAC_LEN];
    if mac_supported {
        for (i, b) in mac.iter_mut().enumerate() {
            *b = unsafe { regs.r8(LEG_MAC + i) };
        }
    }

    rx.prime();
    driver_ok(regs);

    let _ = mk_irq_ack(irq_grant.grant_id);

    Ok(Driver {
        device_id: dev.device_id,
        claim_epoch,
        mmio_grant: mmio_grant.grant_id,
        irq_grant: irq_grant.grant_id,
        rx_queue_grant: rx_queue_dma.grant_id,
        rx_buffer_grant: rx_buf_dma.grant_id,
        tx_queue_grant: tx_queue_dma.grant_id,
        tx_buffer_grant: tx_buf_dma.grant_id,
        rx,
        tx,
        regs,
        mac,
        status_supported,
    })
}
