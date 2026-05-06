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

//! One-shot block-I/O round trip. Posts a descriptor chain, kicks
//! the queue, waits on `MkIrqPoll` with a used-ring fallback, acks
//! the IRQ, and inspects the trailing virtio-blk status byte. The
//! same primitive serves read, write, and flush — only the
//! `Direction` and the data descriptor differ.

use nonos_libc::{mk_irq_ack, mk_irq_poll, mk_yield, IrqPollOut};

use crate::constants::{
    LEG_QUEUE_NOTIFY, VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP,
};
use crate::queue::Queue;
use crate::regs::Regs;

pub use crate::queue::Direction;

const MAX_YIELDS: u32 = 200_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkError {
    Io,
    Unsupported,
    Timeout,
}

pub fn submit(
    regs: Regs,
    queue: &mut Queue,
    irq_grant: u64,
    dir: Direction,
    lba: u64,
    nsectors: u32,
) -> Result<(), BlkError> {
    queue.post_request(dir, lba, nsectors);
    unsafe {
        regs.w16(LEG_QUEUE_NOTIFY, 0);
    }

    let prev_seq = read_seq(irq_grant);
    let target = queue.last_used.wrapping_add(1);

    let mut tries = 0u32;
    loop {
        if queue.used_idx() == target {
            break;
        }
        if read_seq(irq_grant) != prev_seq {
            break;
        }
        if tries >= MAX_YIELDS {
            return Err(BlkError::Timeout);
        }
        let _ = mk_yield();
        tries = tries.wrapping_add(1);
    }
    queue.last_used = target;
    let status = queue.status_byte();
    let _ = mk_irq_ack(irq_grant);

    match status {
        VIRTIO_BLK_S_OK => Ok(()),
        VIRTIO_BLK_S_IOERR => Err(BlkError::Io),
        VIRTIO_BLK_S_UNSUPP => Err(BlkError::Unsupported),
        _ => Err(BlkError::Io),
    }
}

fn read_seq(grant: u64) -> u64 {
    let mut out = IrqPollOut { seq: 0, overflow: 0 };
    let _ = mk_irq_poll(grant, &mut out as *mut _);
    out.seq
}
