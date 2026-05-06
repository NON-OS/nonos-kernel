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

//! Build the virtio-blk descriptor chain — header / data / status —
//! and publish slot 0 of the available ring. The header is always
//! device-read; the data descriptor toggles WRITE for an inbound
//! transfer (read from disk into our buffer) and is read-only for
//! an outbound transfer (write to disk from our buffer); the
//! status byte is always device-write.

use core::ptr::{read_volatile, write_volatile};

use super::layout::Queue;
use crate::constants::{
    HEADER_OFFSET, STATUS_OFFSET, VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT,
    VQ_AVAIL_OFFSET, VQ_DESC_OFFSET, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE,
};

const DESC_SIZE: usize = 16;
const STATUS_LEN: u32 = 1;
const HEADER_LEN: u32 = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Read,
    Write,
    Flush,
}

impl Direction {
    fn req_type(self) -> u32 {
        match self {
            Direction::Read => VIRTIO_BLK_T_IN,
            Direction::Write => VIRTIO_BLK_T_OUT,
            Direction::Flush => VIRTIO_BLK_T_FLUSH,
        }
    }
}

impl Queue {
    /// SAFETY: the descriptor / ring / header / data / status
    /// memory all belong to DMA grants the broker handed the
    /// capsule. Only the capsule writes to them between requests,
    /// and the device reads them after the queue-notify register
    /// is poked.
    pub fn post_request(&self, dir: Direction, lba: u64, nsectors: u32) {
        unsafe {
            self.write_header(dir, lba);
            self.write_descriptor_chain(dir, nsectors);
            self.publish_avail();
        }
    }

    unsafe fn write_header(&self, dir: Direction, lba: u64) {
        let hdr = self.header_va.add(HEADER_OFFSET);
        write_volatile(hdr.cast::<u32>(), dir.req_type());
        write_volatile(hdr.add(4).cast::<u32>(), 0u32);
        write_volatile(hdr.add(8).cast::<u64>(), lba);
        write_volatile(self.header_va.add(STATUS_OFFSET), 0xFFu8);
    }

    unsafe fn write_descriptor_chain(&self, dir: Direction, nsectors: u32) {
        let desc_base = self.region_va.add(VQ_DESC_OFFSET);
        let header_phys = self.header_phys + HEADER_OFFSET as u64;
        let status_phys = self.header_phys + STATUS_OFFSET as u64;

        // Descriptor 0: header — device reads it.
        write_volatile(desc_base.cast::<u64>(), header_phys);
        write_volatile(desc_base.add(8).cast::<u32>(), HEADER_LEN);
        write_volatile(desc_base.add(12).cast::<u16>(), VRING_DESC_F_NEXT);
        write_volatile(desc_base.add(14).cast::<u16>(), 1u16);

        // Descriptor 1: data (or absent for flush).
        if dir == Direction::Flush {
            // Skip data, point straight at status.
            let d2 = desc_base.add(16);
            write_volatile(d2.cast::<u64>(), status_phys);
            write_volatile(d2.add(8).cast::<u32>(), STATUS_LEN);
            write_volatile(d2.add(12).cast::<u16>(), VRING_DESC_F_WRITE);
            write_volatile(d2.add(14).cast::<u16>(), 0u16);
            return;
        }

        let d1 = desc_base.add(16);
        let data_len = nsectors.saturating_mul(crate::constants::SECTOR_SIZE as u32);
        write_volatile(d1.cast::<u64>(), self.data_phys);
        write_volatile(d1.add(8).cast::<u32>(), data_len);
        let data_flags = match dir {
            Direction::Read => VRING_DESC_F_NEXT | VRING_DESC_F_WRITE,
            Direction::Write => VRING_DESC_F_NEXT,
            Direction::Flush => unreachable!("flush handled above"),
        };
        write_volatile(d1.add(12).cast::<u16>(), data_flags);
        write_volatile(d1.add(14).cast::<u16>(), 2u16);

        // Descriptor 2: status — device writes it.
        let d2 = desc_base.add(32);
        write_volatile(d2.cast::<u64>(), status_phys);
        write_volatile(d2.add(8).cast::<u32>(), STATUS_LEN);
        write_volatile(d2.add(12).cast::<u16>(), VRING_DESC_F_WRITE);
        write_volatile(d2.add(14).cast::<u16>(), 0u16);
        let _ = DESC_SIZE;
    }

    unsafe fn publish_avail(&self) {
        let avail = self.region_va.add(VQ_AVAIL_OFFSET).cast::<u16>();
        write_volatile(avail.add(2), 0u16);
        let idx = read_volatile(avail.add(1));
        write_volatile(avail.add(1), idx.wrapping_add(1));
    }
}
