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

use core::{mem, ptr};
use core::sync::atomic::Ordering;
use x86_64::PhysAddr;
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};

const QUEUE_SIZE: u16 = 16;
const BUFFER_SIZE: usize = 4096;
const DMA_ALIGNMENT: usize = 64;
const VIRTQ_DESC_F_WRITE: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE as usize],
    _used_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtqUsedElem {
    _id: u32,
    len: u32,
}

#[repr(C)]
struct VirtqUsed {
    _flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; QUEUE_SIZE as usize],
    _avail_event: u16,
}

struct DmaRegion {
    virt: usize,
    phys: PhysAddr,
}

impl DmaRegion {
    fn new(size: usize) -> Result<Self, &'static str> {
        let constraints = DmaConstraints {
            alignment: DMA_ALIGNMENT,
            max_segment_size: size,
            dma32_only: false,
            coherent: true,
        };

        let region = alloc_dma_coherent(size, constraints)
            .map_err(|_| "Failed to allocate DMA region")?;

        unsafe {
            ptr::write_bytes(region.virt_addr.as_mut_ptr::<u8>(), 0, size);
        }

        Ok(Self {
            virt: region.virt_addr.as_u64() as usize,
            phys: region.phys_addr,
        })
    }
}

pub(super) struct RngQueue {
    desc_region: DmaRegion,
    _avail_region: DmaRegion,
    _used_region: DmaRegion,
    _buffer_region: DmaRegion,
    desc_table: *mut VirtqDesc,
    avail_ring: *mut VirtqAvail,
    used_ring: *mut VirtqUsed,
    buffer: *mut u8,
    buffer_phys: PhysAddr,
    last_used_idx: u16,
    next_avail_idx: u16,
    pending_len: usize,
    notify_port: u16,
    notify_mmio: u64,
}

unsafe impl Send for RngQueue {}
unsafe impl Sync for RngQueue {}

impl RngQueue {
    pub(super) fn new() -> Result<Self, &'static str> {
        let dt_size = QUEUE_SIZE as usize * mem::size_of::<VirtqDesc>();
        let av_size = mem::size_of::<VirtqAvail>();
        let us_size = mem::size_of::<VirtqUsed>();

        let desc_region = DmaRegion::new(dt_size)?;
        let avail_region = DmaRegion::new(av_size)?;
        let used_region = DmaRegion::new(us_size)?;
        let buffer_region = DmaRegion::new(BUFFER_SIZE)?;

        let desc_table = desc_region.virt as *mut VirtqDesc;
        let avail_ring = avail_region.virt as *mut VirtqAvail;
        let used_ring = used_region.virt as *mut VirtqUsed;
        let buffer = buffer_region.virt as *mut u8;
        let buffer_phys = buffer_region.phys;

        Ok(Self {
            desc_region,
            _avail_region: avail_region,
            _used_region: used_region,
            _buffer_region: buffer_region,
            desc_table,
            avail_ring,
            used_ring,
            buffer,
            buffer_phys,
            last_used_idx: 0,
            next_avail_idx: 0,
            pending_len: 0,
            notify_port: 0,
            notify_mmio: 0,
        })
    }

    pub(super) fn desc_table_phys(&self) -> u64 {
        self.desc_region.phys.as_u64()
    }

    pub(super) fn set_notify_addr(&mut self, port: u16) {
        self.notify_port = port;
    }

    pub(super) fn set_notify_mmio(&mut self, addr: u64) {
        self.notify_mmio = addr;
    }

    pub(super) fn request_random(&mut self, len: usize) -> Result<(), &'static str> {
        let len = len.min(BUFFER_SIZE);
        self.pending_len = len;

        unsafe {
            ptr::write_bytes(self.buffer, 0, BUFFER_SIZE);
            let desc = &mut *self.desc_table;
            desc.addr = self.buffer_phys.as_u64();
            desc.len = len as u32;
            desc.flags = VIRTQ_DESC_F_WRITE;
            desc.next = 0;

            let avail = &mut *self.avail_ring;
            let idx = self.next_avail_idx;
            avail.ring[(idx % QUEUE_SIZE) as usize] = 0;
            core::sync::atomic::fence(Ordering::SeqCst);
            self.next_avail_idx = self.next_avail_idx.wrapping_add(1);
            avail.idx = self.next_avail_idx;
        }

        self.kick();
        Ok(())
    }

    pub(super) fn has_completed(&self) -> bool {
        unsafe {
            let used = &*self.used_ring;
            used.idx != self.last_used_idx
        }
    }

    pub(super) fn get_received_bytes(&mut self, buf: &mut [u8]) -> usize {
        let received_len = unsafe {
            let used = &*self.used_ring;
            if used.idx == self.last_used_idx {
                return 0;
            }
            let used_elem = &used.ring[(self.last_used_idx % QUEUE_SIZE) as usize];
            self.last_used_idx = self.last_used_idx.wrapping_add(1);
            used_elem.len as usize
        };

        let copy_len = received_len.min(buf.len()).min(self.pending_len);
        unsafe {
            ptr::copy_nonoverlapping(self.buffer, buf.as_mut_ptr(), copy_len);
        }
        self.pending_len = 0;
        copy_len
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
