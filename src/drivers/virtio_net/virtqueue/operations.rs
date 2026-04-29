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

use alloc::{sync::Arc, vec::Vec};
use core::{mem, ptr};
use core::sync::atomic::Ordering;
use spin::Mutex;

use super::super::buffer::PacketBuffer;
use super::super::constants::*;
use super::core::VirtQueue;
use super::descriptors::{VirtqAvail, VirtqUsedElem};

impl VirtQueue {
    pub fn alloc_desc_chain(&mut self, count: usize) -> Option<Vec<u16>> {
        if count == 0 || count > MAX_DESC_CHAIN_LEN {
            return None;
        }

        if self.free_descriptors.len() < count {
            return None;
        }

        let mut chain = Vec::with_capacity(count);
        for _ in 0..count {
            let idx = self.free_descriptors.pop_front()?;

            if idx >= self.queue_size {
                for &ret_idx in &chain {
                    self.free_descriptors.push_back(ret_idx);
                }
                return None;
            }

            chain.push(idx);
        }

        for i in 0..(count.saturating_sub(1)) {
            // SAFETY: chain indices are validated above
            unsafe {
                let d = &mut *self.desc_table.add(chain[i] as usize);
                d.next = chain[i + 1];
                d.flags |= VIRTQ_DESC_F_NEXT;
            }
        }

        if let Some(&last_idx) = chain.last() {
            // SAFETY: last_idx is validated above
            unsafe {
                let d = &mut *self.desc_table.add(last_idx as usize);
                d.flags &= !VIRTQ_DESC_F_NEXT;
            }
        }

        Some(chain)
    }

    pub fn free_desc_chain(&mut self, chain: Vec<u16>) {
        for idx in chain {
            if idx >= self.queue_size {
                continue;
            }

            // SAFETY: idx is bounds-checked above
            unsafe {
                ptr::write_bytes(self.desc_table.add(idx as usize), 0, 1);
            }

            let idx_usize = idx as usize;
            if idx_usize < self.rx_owner.len() {
                self.rx_owner[idx_usize] = None;
            }
            if idx_usize < self.tx_owner.len() {
                self.tx_owner[idx_usize] = None;
            }

            self.free_descriptors.push_back(idx);
        }
    }

    pub fn add_to_avail_ring(&mut self, desc_idx: u16) {
        if desc_idx >= self.queue_size {
            return;
        }

        // SAFETY: avail_ring is valid DMA memory, desc_idx is bounds-checked
        unsafe {
            let base = self.avail_ring as *mut u8;
            let ring = base.add(mem::size_of::<VirtqAvail>()) as *mut u16;

            let idx = self.next_avail_idx % self.queue_size;
            *ring.add(idx as usize) = desc_idx;

            core::sync::atomic::fence(Ordering::SeqCst);

            self.next_avail_idx = self.next_avail_idx.wrapping_add(1);
            (*self.avail_ring).idx = self.next_avail_idx;
        }
    }

    pub fn get_used_buffers(&mut self) -> Vec<(u16, u32)> {
        let mut out = Vec::new();

        // SAFETY: used_ring is valid DMA memory
        unsafe {
            let cur = (*self.used_ring).idx;

            let max_iterations = self.queue_size as usize;
            let mut iterations = 0;

            while self.last_used_idx != cur && iterations < max_iterations {
                let used_bytes = self.used_ring as *mut u8;
                let ring = used_bytes.add(mem::size_of::<super::descriptors::VirtqUsed>())
                    as *mut VirtqUsedElem;
                let i = self.last_used_idx % self.queue_size;
                let u = *ring.add(i as usize);

                let desc_id = u.id as u16;
                if desc_id < self.queue_size {
                    out.push((desc_id, u.len));
                }

                self.last_used_idx = self.last_used_idx.wrapping_add(1);
                iterations += 1;
            }
        }

        out
    }

    pub fn set_rx_owner(&mut self, desc: u16, buf: Arc<Mutex<PacketBuffer>>) {
        let idx = desc as usize;
        if idx < self.rx_owner.len() {
            self.rx_owner[idx] = Some(buf);
        }
    }

    pub fn take_rx_owner(&mut self, desc: u16) -> Option<Arc<Mutex<PacketBuffer>>> {
        let idx = desc as usize;
        if idx < self.rx_owner.len() {
            self.rx_owner[idx].take()
        } else {
            None
        }
    }

    pub fn set_tx_owner(&mut self, desc: u16, buf: Arc<Mutex<PacketBuffer>>) {
        let idx = desc as usize;
        if idx < self.tx_owner.len() {
            self.tx_owner[idx] = Some(buf);
        }
    }

    pub fn take_tx_owner(&mut self, desc: u16) -> Option<Arc<Mutex<PacketBuffer>>> {
        let idx = desc as usize;
        if idx < self.tx_owner.len() {
            self.tx_owner[idx].take()
        } else {
            None
        }
    }
}
