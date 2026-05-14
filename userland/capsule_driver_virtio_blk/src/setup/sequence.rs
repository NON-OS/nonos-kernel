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

//! End-to-end setup: discover -> claim -> MMIO -> IRQ -> queue/
//! header/data DMA -> virtio init -> capacity read -> first IRQ
//! unmask. Each phase emits a marker; failure inside any phase
//! is rolled back by the corresponding helper before this
//! function ever returns.

use nonos_libc::mk_irq_ack;

use super::driver::Driver;
use super::{claim, dma, irq, mmio};
use crate::constants::LEG_CFG_CAPACITY;
use crate::discover::find_virtio_blk;
use crate::init::bring_up;
use crate::queue::Queue;
use crate::regs::Regs;

pub fn run() -> Result<Driver, &'static str> {
    let dev = find_virtio_blk().ok_or("no virtio-blk device")?;

    let claim_epoch = claim::claim(dev.device_id)?;

    let mmio_grant = mmio::map(dev, claim_epoch)?;

    let irq_grant = irq::bind(dev, claim_epoch, &mmio_grant)?;

    let queue_dma = dma::map_queue(dev.device_id, claim_epoch, &mmio_grant, &irq_grant)?;
    let header_dma =
        dma::map_header(dev.device_id, claim_epoch, &mmio_grant, &irq_grant, &queue_dma)?;
    let data_dma = dma::map_data(
        dev.device_id,
        claim_epoch,
        &mmio_grant,
        &irq_grant,
        &queue_dma,
        &header_dma,
    )?;

    let regs = Regs::new(mmio_grant.user_va);
    let init = bring_up(regs, queue_dma.device_addr, Queue::queue_size())?;
    let queue = Queue::new(
        queue_dma.user_va,
        queue_dma.device_addr,
        header_dma.user_va,
        header_dma.device_addr,
        data_dma.user_va,
        data_dma.device_addr,
    );

    let capacity_sectors = unsafe { regs.r64(LEG_CFG_CAPACITY) };
    if capacity_sectors == 0 {
        return Err("virtio-blk: zero capacity");
    }

    let _ = mk_irq_ack(irq_grant.grant_id);
    let _ = init.queue_size;

    Ok(Driver {
        device_id: dev.device_id,
        claim_epoch,
        mmio_grant: mmio_grant.grant_id,
        irq_grant: irq_grant.grant_id,
        queue_grant: queue_dma.grant_id,
        header_grant: header_dma.grant_id,
        data_grant: data_dma.grant_id,
        queue,
        regs,
        capacity_sectors,
        flush_supported: init.flush_supported,
    })
}
