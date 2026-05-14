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

use core::ptr::write_volatile;

use super::Submission;
use crate::constants::REG_DOORBELL_BASE;
use crate::dma::DmaRegion;
use crate::error::NvmeResult;
use crate::regs::Regs;

mod log;
mod registers;
mod wait;

const ADMIN_ENTRIES: u16 = 64;
const SQ_BYTES: u64 = 4096;
const CQ_BYTES: u64 = 4096;
const IDENTIFY_BYTES: u64 = 4096;
const COMPLETION_POLL_LIMIT: u32 = 5_000_000;

pub struct AdminQueue {
    sq: DmaRegion,
    cq: DmaRegion,
    identify: DmaRegion,
    tail: u16,
    head: u16,
    phase: bool,
    cid: u16,
}

impl AdminQueue {
    pub fn allocate(device_id: u64, epoch: u64) -> NvmeResult<Self> {
        Ok(Self {
            sq: DmaRegion::map(device_id, epoch, SQ_BYTES)?,
            cq: DmaRegion::map(device_id, epoch, CQ_BYTES)?,
            identify: DmaRegion::map(device_id, epoch, IDENTIFY_BYTES)?,
            tail: 0,
            head: 0,
            phase: true,
            cid: 1,
        })
    }

    pub fn identify_controller(&mut self, regs: Regs, stride: u8) -> NvmeResult<&[u8]> {
        let cid = self.cid;
        self.cid = self.cid.wrapping_add(1).max(1);
        self.submit(
            regs,
            stride,
            Submission::identify_controller(cid, self.identify.device_addr()),
        );
        self.wait(regs, stride, cid)?;
        Ok(unsafe { core::slice::from_raw_parts(self.identify.user_va() as *const u8, 4096) })
    }

    pub fn identify_namespace(&mut self, regs: Regs, stride: u8, nsid: u32) -> NvmeResult<&[u8]> {
        let cid = self.cid;
        self.cid = self.cid.wrapping_add(1).max(1);
        self.submit(
            regs,
            stride,
            Submission::identify_namespace(cid, nsid, self.identify.device_addr()),
        );
        self.wait(regs, stride, cid)?;
        Ok(unsafe { core::slice::from_raw_parts(self.identify.user_va() as *const u8, 4096) })
    }

    fn submit(&mut self, regs: Regs, stride: u8, cmd: Submission) {
        let slot =
            self.sq.user_va() + (self.tail as u64) * (core::mem::size_of::<Submission>() as u64);
        unsafe { write_volatile(slot as *mut Submission, cmd) };
        self.tail = (self.tail + 1) % ADMIN_ENTRIES;
        unsafe { regs.w32(sq0_tail(stride), self.tail as u32) };
    }
}

const fn sq0_tail(stride: u8) -> u32 {
    let _ = stride;
    REG_DOORBELL_BASE
}

const fn cq0_head(stride: u8) -> u32 {
    REG_DOORBELL_BASE + ((4u32) << stride)
}
