// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{mem, ptr};
use core::sync::atomic::Ordering;
use spin::Mutex;
use x86_64::PhysAddr;
use super::buffer::PacketBuffer;
use super::constants::*;
use super::dma::DmaRegion;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

impl VirtqDesc {
    pub const SIZE: usize = 16;
    pub const fn new() -> Self {
        Self {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }
    }

    pub fn has_next(&self) -> bool {
        (self.flags & VIRTQ_DESC_F_NEXT) != 0
    }

    pub fn is_write(&self) -> bool {
        (self.flags & VIRTQ_DESC_F_WRITE) != 0
    }

    pub fn is_indirect(&self) -> bool {
        (self.flags & VIRTQ_DESC_F_INDIRECT) != 0
    }

    pub fn clear(&mut self) {
        self.addr = 0;
        self.len = 0;
        self.flags = 0;
        self.next = 0;
    }
}

#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; 0],
}

pub struct VirtQueue {
    pub queue_size: u16,
    _desc_region: DmaRegion,
    _avail_region: DmaRegion,
    _used_region: DmaRegion,
    pub desc_table: *mut VirtqDesc,
    pub avail_ring: *mut VirtqAvail,
    pub used_ring: *mut VirtqUsed,
    pub desc_table_phys: PhysAddr,
    pub avail_ring_phys: PhysAddr,
    pub used_ring_phys: PhysAddr,
    pub free_descriptors: VecDeque<u16>,
    pub last_used_idx: u16,
    pub next_avail_idx: u16,
    rx_owner: Vec<Option<Arc<Mutex<PacketBuffer>>>>,
    tx_owner: Vec<Option<Arc<Mutex<PacketBuffer>>>>,
    notify_addr: usize,
}

// SAFETY: VirtQueue uses DMA memory and atomic operations correctly
unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}
impl VirtQueue {
    pub fn new(queue_size: u16) -> Result<Self, &'static str> {
        if !queue_size.is_power_of_two() {
            return Err("virtq: queue_size must be power of two");
        }

        if queue_size == 0 {
            return Err("virtq: queue_size cannot be zero");
        }

        let dt_size = queue_size as usize * mem::size_of::<VirtqDesc>();
        let av_size = mem::size_of::<VirtqAvail>() + (queue_size as usize * 2) + 2;
        let us_size = mem::size_of::<VirtqUsed>()
            + (queue_size as usize * mem::size_of::<VirtqUsedElem>())
            + 2;

        let desc_region = DmaRegion::new(dt_size)?;
        let avail_region = DmaRegion::new(av_size)?;
        let used_region = DmaRegion::new(us_size)?;
        let desc_table = desc_region.as_mut_ptr::<VirtqDesc>();
        let avail_ring = avail_region.as_mut_ptr::<VirtqAvail>();
        let used_ring = used_region.as_mut_ptr::<VirtqUsed>();
        let mut free = VecDeque::with_capacity(queue_size as usize);
        for i in 0..queue_size {
            free.push_back(i);
        }

        let desc_table_phys = desc_region.phys();
        let avail_ring_phys = avail_region.phys();
        let used_ring_phys = used_region.phys();
        let rx_owner = vec![None; queue_size as usize];
        let tx_owner = vec![None; queue_size as usize];
        Ok(Self {
            queue_size,
            _desc_region: desc_region,
            _avail_region: avail_region,
            _used_region: used_region,
            desc_table,
            avail_ring,
            used_ring,
            desc_table_phys,
            avail_ring_phys,
            used_ring_phys,
            free_descriptors: free,
            last_used_idx: 0,
            next_avail_idx: 0,
            rx_owner,
            tx_owner,
            notify_addr: 0,
        })
    }

    pub fn set_notify_addr(&mut self, addr: usize) {
        self.notify_addr = addr;
    }

    pub fn get_notify_addr(&self) -> usize {
        self.notify_addr
    }

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

    pub fn kick(&self) {
        if self.notify_addr != 0 {
            core::sync::atomic::fence(Ordering::SeqCst);
            // SAFETY: notify_addr points to valid MMIO notification register
            unsafe {
                ptr::write_volatile(self.notify_addr as *mut u16, 0u16);
            }
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
                let ring = used_bytes.add(mem::size_of::<VirtqUsed>()) as *mut VirtqUsedElem;
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

    pub fn has_used_buffers(&self) -> bool {
        // SAFETY: used_ring is valid DMA memory
        unsafe { (*self.used_ring).idx != self.last_used_idx }
    }

    pub fn available_descriptors(&self) -> usize {
        self.free_descriptors.len()
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

    pub unsafe fn get_desc(&self, idx: u16) -> Option<&VirtqDesc> {
        if idx < self.queue_size {
            Some(&*self.desc_table.add(idx as usize))
        } else {
            None
        }
    }

    pub unsafe fn get_desc_mut(&mut self, idx: u16) -> Option<&mut VirtqDesc> {
        if idx < self.queue_size {
            Some(&mut *self.desc_table.add(idx as usize))
        } else {
            None
        }
    }
}

impl Drop for VirtQueue {
    fn drop(&mut self) {
        // SAFETY: desc_table is valid DMA memory we own
        unsafe {
            ptr::write_bytes(
                self.desc_table,
                0,
                self.queue_size as usize,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtq_desc_size() {
        assert_eq!(VirtqDesc::SIZE, 16);
        assert_eq!(mem::size_of::<VirtqDesc>(), 16);
    }

    #[test]
    fn test_virtq_desc_flags() {
        let mut desc = VirtqDesc::new();
        assert!(!desc.has_next());
        assert!(!desc.is_write());

        desc.flags = VIRTQ_DESC_F_NEXT;
        assert!(desc.has_next());

        desc.flags = VIRTQ_DESC_F_WRITE;
        assert!(desc.is_write());
    }

    #[test]
    fn test_virtq_desc_clear() {
        let mut desc = VirtqDesc {
            addr: 0x1234,
            len: 100,
            flags: VIRTQ_DESC_F_NEXT,
            next: 5,
        };
        desc.clear();
        assert_eq!(desc.addr, 0);
        assert_eq!(desc.len, 0);
        assert_eq!(desc.flags, 0);
        assert_eq!(desc.next, 0);
    }
}
