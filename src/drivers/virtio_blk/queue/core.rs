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

use super::constants::{DATA_BUF_SIZE, VQ_REGION_SIZE};
use super::types::{BlkDataBuf, VirtqueueRegionBuf};
use core::ptr;

static mut VQ_REGION: VirtqueueRegionBuf = VirtqueueRegionBuf([0u8; VQ_REGION_SIZE]);
static mut DATA_BUF: BlkDataBuf = BlkDataBuf([0u8; DATA_BUF_SIZE]);

pub(crate) struct BlkQueue {
    pub(super) vq_base: usize,
    pub(super) buf_base: usize,
    pub(super) last_used_idx: u16,
    pub(super) next_avail_idx: u16,
    pub(super) next_desc_idx: u16,
    pub(super) notify_port: u16,
    pub(super) notify_mmio: u64,
}

unsafe impl Send for BlkQueue {}
unsafe impl Sync for BlkQueue {}

impl BlkQueue {
    pub(crate) fn new() -> Result<Self, &'static str> {
        let vq_base = ptr::addr_of!(VQ_REGION) as usize;
        let buf_base = ptr::addr_of!(DATA_BUF) as usize;
        if vq_base & 0xFFF != 0 {
            return Err("virtio-blk: VQ not aligned");
        }
        if buf_base & 0xFFF != 0 {
            return Err("virtio-blk: buffer not aligned");
        }
        unsafe {
            ptr::write_bytes(vq_base as *mut u8, 0, VQ_REGION_SIZE);
            ptr::write_bytes(buf_base as *mut u8, 0, DATA_BUF_SIZE);
        }
        Ok(Self {
            vq_base,
            buf_base,
            last_used_idx: 0,
            next_avail_idx: 0,
            next_desc_idx: 0,
            notify_port: 0,
            notify_mmio: 0,
        })
    }

    pub(crate) fn desc_table_phys(&self) -> u64 {
        self.vq_base as u64
    }
    pub(crate) fn set_notify_addr(&mut self, port: u16) {
        self.notify_port = port;
    }
    pub(crate) fn set_notify_mmio(&mut self, addr: u64) {
        self.notify_mmio = addr;
    }
}
