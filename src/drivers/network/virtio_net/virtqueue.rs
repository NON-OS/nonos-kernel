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

use super::constants::QUEUE_SIZE;
use super::descriptors::{VirtqAvail, VirtqDesc, VirtqUsed};

pub struct VirtqueuePtrs {
    desc: usize,
    avail: usize,
    used: usize,
}

pub struct Virtqueue {
    pub ptrs: VirtqueuePtrs,
    pub free_head: u16,
    pub num_free: u16,
    pub last_used_idx: u16,
}

unsafe impl Send for Virtqueue {}
unsafe impl Sync for Virtqueue {}

impl Virtqueue {
    pub fn new(
        desc: *mut [VirtqDesc; QUEUE_SIZE],
        avail: *mut VirtqAvail,
        used: *mut VirtqUsed,
    ) -> Self {
        Self {
            ptrs: VirtqueuePtrs { desc: desc as usize, avail: avail as usize, used: used as usize },
            free_head: 0,
            num_free: QUEUE_SIZE as u16,
            last_used_idx: 0,
        }
    }

    fn desc(&self) -> *mut [VirtqDesc; QUEUE_SIZE] {
        self.ptrs.desc as *mut [VirtqDesc; QUEUE_SIZE]
    }
    fn avail(&self) -> *mut VirtqAvail {
        self.ptrs.avail as *mut VirtqAvail
    }
    fn used(&self) -> *mut VirtqUsed {
        self.ptrs.used as *mut VirtqUsed
    }

    pub unsafe fn setup_free_list(&mut self) {
        for i in 0..(QUEUE_SIZE - 1) {
            (*self.desc())[i].next = (i + 1) as u16;
        }
        (*self.desc())[QUEUE_SIZE - 1].next = 0xFFFF;
        self.free_head = 0;
        self.num_free = QUEUE_SIZE as u16;
    }

    pub unsafe fn alloc_desc(&mut self) -> Option<u16> {
        if self.num_free == 0 {
            return None;
        }
        let idx = self.free_head;
        self.free_head = (*self.desc())[idx as usize].next;
        self.num_free -= 1;
        Some(idx)
    }

    pub unsafe fn free_desc(&mut self, idx: u16) {
        (*self.desc())[idx as usize].next = self.free_head;
        self.free_head = idx;
        self.num_free += 1;
    }

    pub unsafe fn add_buffer(&mut self, desc_idx: u16) {
        let avail_idx = (*self.avail()).idx as usize % QUEUE_SIZE;
        (*self.avail()).ring[avail_idx] = desc_idx;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        (*self.avail()).idx = (*self.avail()).idx.wrapping_add(1);
    }

    pub unsafe fn has_used(&self) -> bool {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.last_used_idx != (*self.used()).idx
    }
}
