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

//! Build descriptor entries on the RX and TX rings. RX uses one
//! descriptor per buffer with the device-write flag set; TX uses
//! a single device-read descriptor reused per outbound packet.
//! Both publish the descriptor index into the available ring and
//! bump `idx` last so the device never sees a half-written slot.

use core::ptr::{read_volatile, write_volatile};

use super::layout::{RxQueue, TxQueue};
use crate::constants::{VQ_AVAIL_OFFSET, VQ_DESC_OFFSET, VRING_DESC_F_WRITE};

const DESC_SIZE: usize = 16;
const AVAIL_RING_OFFSET: usize = 4;

impl RxQueue {
    /// Lay out one device-write descriptor per RX buffer in the
    /// pool, then publish all of them in the available ring at
    /// once. Called exactly once before DRIVER_OK; the runtime
    /// loop refills slots as their used entries land.
    pub fn prime(&self) {
        unsafe {
            let desc_base = self.region_va.add(VQ_DESC_OFFSET);
            let avail = self.region_va.add(VQ_AVAIL_OFFSET).cast::<u16>();
            for i in 0..self.buf_count {
                let slot = desc_base.add(DESC_SIZE * i as usize);
                let buf_phys = self.buf_phys + (self.buf_len as u64) * (i as u64);
                write_volatile(slot.cast::<u64>(), buf_phys);
                write_volatile(slot.add(8).cast::<u32>(), self.buf_len);
                write_volatile(slot.add(12).cast::<u16>(), VRING_DESC_F_WRITE);
                write_volatile(slot.add(14).cast::<u16>(), 0u16);
                write_volatile(avail.add(2 + i as usize), i);
            }
            write_volatile(avail.add(1), self.buf_count);
        }
    }

    /// Re-publish a single RX descriptor whose used entry has
    /// been consumed. Caller bumped `last_used` already; this
    /// hands the slot back to the device.
    pub fn refill(&self, slot: u16) {
        unsafe {
            let avail = self.region_va.add(VQ_AVAIL_OFFSET).cast::<u16>();
            let idx = read_volatile(avail.add(1));
            let pos = (idx as usize) % (self.buf_count as usize);
            write_volatile(avail.add(2 + pos), slot);
            write_volatile(avail.add(1), idx.wrapping_add(1));
        }
    }
}

impl TxQueue {
    /// Stage a single outbound packet on descriptor 0 and publish
    /// slot 0 in the available ring. The device sees the request
    /// after the queue-notify register is poked next.
    pub fn post_packet(&self, length: u32) {
        unsafe {
            let desc_base = self.region_va.add(VQ_DESC_OFFSET);
            write_volatile(desc_base.cast::<u64>(), self.buf_phys);
            write_volatile(desc_base.add(8).cast::<u32>(), length);
            write_volatile(desc_base.add(12).cast::<u16>(), 0u16);
            write_volatile(desc_base.add(14).cast::<u16>(), 0u16);

            let avail = self.region_va.add(VQ_AVAIL_OFFSET).cast::<u16>();
            write_volatile(avail.add(AVAIL_RING_OFFSET / 2), 0u16);
            let idx = read_volatile(avail.add(1));
            write_volatile(avail.add(1), idx.wrapping_add(1));
        }
    }
}
