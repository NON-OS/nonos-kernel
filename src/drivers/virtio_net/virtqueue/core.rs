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

use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{mem, ptr};
use core::sync::atomic::Ordering;
use spin::Mutex;
use x86_64::PhysAddr;

use super::super::buffer::PacketBuffer;
use super::super::dma::DmaRegion;
use super::descriptors::{VirtqAvail, VirtqDesc, VirtqUsed};

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

    pub(super) rx_owner: Vec<Option<Arc<Mutex<PacketBuffer>>>>,
    pub(super) tx_owner: Vec<Option<Arc<Mutex<PacketBuffer>>>>,

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
            + (queue_size as usize * mem::size_of::<super::descriptors::VirtqUsedElem>())
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

    pub fn kick(&self) {
        if self.notify_addr != 0 {
            core::sync::atomic::fence(Ordering::SeqCst);
            // SAFETY: notify_addr points to valid MMIO notification register
            unsafe {
                ptr::write_volatile(self.notify_addr as *mut u16, 0u16);
            }
        }
    }

    pub fn available_descriptors(&self) -> usize {
        self.free_descriptors.len()
    }

    pub fn has_used_buffers(&self) -> bool {
        // SAFETY: used_ring is valid DMA memory
        unsafe { (*self.used_ring).idx != self.last_used_idx }
    }

    pub unsafe fn get_desc(&self, idx: u16) -> Option<&VirtqDesc> {
        unsafe {
            if idx < self.queue_size {
                Some(&*self.desc_table.add(idx as usize))
            } else {
                None
            }
        }
    }

    pub unsafe fn get_desc_mut(&mut self, idx: u16) -> Option<&mut VirtqDesc> {
        unsafe {
            if idx < self.queue_size {
                Some(&mut *self.desc_table.add(idx as usize))
            } else {
                None
            }
        }
    }
}

impl Drop for VirtQueue {
    fn drop(&mut self) {
        // SAFETY: desc_table is valid DMA memory we own
        unsafe {
            ptr::write_bytes(self.desc_table, 0, self.queue_size as usize);
        }
    }
}
