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
use super::{claim, dma, irq, registers, trace};
use crate::constants::LEG_CFG_CAPACITY;
use crate::discover::find_virtio_blk;
use crate::init::bring_up;
use crate::queue::Queue;

pub fn run() -> Result<Driver, &'static str> {
    let dev = find_virtio_blk().ok_or("no virtio-blk device")?;
    trace::mark(b"[driver_blk] discover ok\n");

    let claim_epoch = claim::claim(dev.device_id)?;
    trace::mark(b"[driver_blk] claim ok\n");

    let register_grant = registers::grant(dev, claim_epoch)?;
    trace::mark(b"[driver_blk] register ok\n");

    let irq_grant = irq::bind(dev, claim_epoch, register_grant)?;
    trace::mark(b"[driver_blk] irq ok\n");

    let queue_dma = dma::map_queue(dev.device_id, claim_epoch, register_grant, &irq_grant)?;
    let header_dma =
        dma::map_header(dev.device_id, claim_epoch, register_grant, &irq_grant, &queue_dma)?;
    let data_dma = dma::map_data(
        dev.device_id,
        claim_epoch,
        register_grant,
        &irq_grant,
        &queue_dma,
        &header_dma,
    )?;
    trace::mark(b"[driver_blk] dma ok\n");

    let regs = register_grant.regs();
    let init = bring_up(regs, queue_dma.device_addr, Queue::max_supported_size())?;
    trace::mark(b"[driver_blk] virtqueue ok\n");
    let queue = Queue::new(
        queue_dma.user_va,
        queue_dma.device_addr,
        init.queue_size,
        header_dma.user_va,
        header_dma.device_addr,
        data_dma.user_va,
        data_dma.device_addr,
    );

    let capacity_sectors = unsafe { regs.r64(LEG_CFG_CAPACITY) };
    if capacity_sectors == 0 {
        return Err("virtio-blk: zero capacity");
    }
    trace::mark(b"[driver_blk] capacity ok\n");

    let _ = mk_irq_ack(irq_grant.grant_id);

    Ok(Driver { irq_grant: irq_grant.grant_id, queue, regs, capacity_sectors })
}
