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

use super::constants::{
    AVAIL_OFFSET, DESC_OFFSET, QUEUE_SIZE, USED_OFFSET, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
};
use super::core::BlkQueue;
use super::types::{VirtqAvail, VirtqDesc, VirtqUsed};
use crate::drivers::virtio_blk::constants::{SECTOR_SIZE, VIRTIO_BLK_S_OK};
use crate::drivers::virtio_blk::types::VirtioBlkReqHeader;
use core::ptr;
use core::sync::atomic::Ordering;

impl BlkQueue {
    fn desc_ptr(&self) -> *mut VirtqDesc {
        (self.vq_base + DESC_OFFSET) as *mut VirtqDesc
    }
    fn avail_ptr(&self) -> *mut VirtqAvail {
        (self.vq_base + AVAIL_OFFSET) as *mut VirtqAvail
    }
    pub(super) fn used_ptr(&self) -> *mut VirtqUsed {
        (self.vq_base + USED_OFFSET) as *mut VirtqUsed
    }

    pub(crate) fn submit_request(
        &mut self,
        req_type: u32,
        sector: u64,
        data: &[u8],
        write: bool,
    ) -> Result<(), &'static str> {
        if self.next_desc_idx + 3 > QUEUE_SIZE {
            return Err("queue full");
        }
        let hdr_off = (self.next_desc_idx as usize) * 16;
        let data_off = 4096 + (self.next_desc_idx as usize) * SECTOR_SIZE * 8;
        let status_off = data_off + data.len();
        let hdr = VirtioBlkReqHeader { req_type, reserved: 0, sector };
        unsafe {
            ptr::copy_nonoverlapping(
                &hdr as *const _ as *const u8,
                (self.buf_base + hdr_off) as *mut u8,
                16,
            );
        }
        if write {
            unsafe {
                ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    (self.buf_base + data_off) as *mut u8,
                    data.len(),
                );
            }
        }
        unsafe {
            ptr::write_bytes((self.buf_base + status_off) as *mut u8, 0xFF, 1);
        }
        self.setup_descriptors(hdr_off, data_off, data.len(), status_off, write);
        self.kick();
        Ok(())
    }

    fn setup_descriptors(
        &mut self,
        hdr_off: usize,
        data_off: usize,
        data_len: usize,
        status_off: usize,
        write: bool,
    ) {
        let base_idx = self.next_desc_idx;
        unsafe {
            let descs = self.desc_ptr();
            (*descs.add(base_idx as usize)) = VirtqDesc {
                addr: (self.buf_base + hdr_off) as u64,
                len: 16,
                flags: VIRTQ_DESC_F_NEXT,
                next: base_idx + 1,
            };
            let data_flags =
                if write { VIRTQ_DESC_F_NEXT } else { VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE };
            (*descs.add((base_idx + 1) as usize)) = VirtqDesc {
                addr: (self.buf_base + data_off) as u64,
                len: data_len as u32,
                flags: data_flags,
                next: base_idx + 2,
            };
            (*descs.add((base_idx + 2) as usize)) = VirtqDesc {
                addr: (self.buf_base + status_off) as u64,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            };
            let avail = &mut *self.avail_ptr();
            avail.ring[(self.next_avail_idx % QUEUE_SIZE) as usize] = base_idx;
            core::sync::atomic::fence(Ordering::SeqCst);
            self.next_avail_idx = self.next_avail_idx.wrapping_add(1);
            avail.idx = self.next_avail_idx;
        }
        self.next_desc_idx += 3;
    }

    pub(crate) fn has_completed(&self) -> bool {
        unsafe { (*self.used_ptr()).idx != self.last_used_idx }
    }

    pub(crate) fn complete_request(&mut self, buf: &mut [u8]) -> Result<usize, u8> {
        unsafe {
            let used = &*self.used_ptr();
            if used.idx == self.last_used_idx {
                return Ok(0);
            }
            let elem = &used.ring[(self.last_used_idx % QUEUE_SIZE) as usize];
            let desc_idx = elem.id as u16;
            let data_off = 4096 + (desc_idx as usize / 3) * SECTOR_SIZE * 8;
            let status_off = data_off + buf.len();
            let status = ptr::read_volatile((self.buf_base + status_off) as *const u8);
            if status != VIRTIO_BLK_S_OK {
                self.last_used_idx = self.last_used_idx.wrapping_add(1);
                return Err(status);
            }
            ptr::copy_nonoverlapping(
                (self.buf_base + data_off) as *const u8,
                buf.as_mut_ptr(),
                buf.len(),
            );
            self.last_used_idx = self.last_used_idx.wrapping_add(1);
            Ok(buf.len())
        }
    }

    fn kick(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
        if self.notify_port != 0 {
            unsafe {
                core::arch::asm!("out dx, ax", in("dx") self.notify_port, in("ax") 0u16, options(nostack, preserves_flags));
            }
        } else if self.notify_mmio != 0 {
            unsafe {
                ptr::write_volatile(self.notify_mmio as *mut u16, 0);
            }
        }
    }
}
