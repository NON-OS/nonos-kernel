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

use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU16, Ordering};
use x86_64::VirtAddr;

use super::super::constants::SUBMISSION_ENTRY_SIZE;
use super::super::dma::DmaRegion;
use super::super::error::NvmeError;
use super::super::types::SubmissionEntry;
use crate::memory::mmio::mmio_w32;

pub struct SubmissionQueue {
    region: DmaRegion,
    entries: NonNull<SubmissionEntry>,
    depth: u16,
    tail: AtomicU16,
    doorbell_addr: usize,
    qid: u16,
}

impl SubmissionQueue {
    pub fn new(qid: u16, depth: u16, doorbell_addr: usize) -> Result<Self, NvmeError> {
        if depth == 0 || depth > 4096 {
            return Err(NvmeError::InvalidQueueSize);
        }

        let size = (depth as usize) * SUBMISSION_ENTRY_SIZE;
        let region = DmaRegion::allocate_aligned(size, 4096)?;

        let entries = NonNull::new(region.as_mut_ptr::<SubmissionEntry>())
            .ok_or(NvmeError::SubmissionQueueError)?;

        Ok(Self {
            region,
            entries,
            depth,
            tail: AtomicU16::new(0),
            doorbell_addr,
            qid,
        })
    }

    #[inline]
    pub const fn qid(&self) -> u16 {
        self.qid
    }

    #[inline]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    #[inline]
    pub fn phys_addr(&self) -> u64 {
        self.region.phys_u64()
    }

    #[inline]
    pub fn tail(&self) -> u16 {
        self.tail.load(Ordering::Acquire)
    }

    pub fn submit(&self, mut entry: SubmissionEntry) -> Result<u16, NvmeError> {
        let tail = self.tail.load(Ordering::Acquire);
        let cid = tail;

        entry.set_cid(cid);
        entry.sanitize();

        let index = (tail as usize) % (self.depth as usize);

        // SAFETY: index is within bounds, pointer is valid and aligned
        unsafe {
            let slot = self.entries.as_ptr().add(index);
            ptr::write_volatile(slot, entry);
        }

        let new_tail = tail.wrapping_add(1) % self.depth;
        self.tail.store(new_tail, Ordering::Release);

        self.ring_doorbell(new_tail);

        Ok(cid)
    }

    pub fn submit_batch(&self, entries: &[SubmissionEntry]) -> Result<alloc::vec::Vec<u16>, NvmeError> {
        let mut cids = alloc::vec::Vec::with_capacity(entries.len());
        let mut tail = self.tail.load(Ordering::Acquire);

        for entry in entries {
            let cid = tail;
            let mut cmd = *entry;
            cmd.set_cid(cid);
            cmd.sanitize();

            let index = (tail as usize) % (self.depth as usize);
            // SAFETY: index is within bounds, pointer is valid and aligned
            unsafe {
                let slot = self.entries.as_ptr().add(index);
                ptr::write_volatile(slot, cmd);
            }

            cids.push(cid);
            tail = tail.wrapping_add(1) % self.depth;
        }

        self.tail.store(tail, Ordering::Release);
        self.ring_doorbell(tail);

        Ok(cids)
    }

    #[inline]
    fn ring_doorbell(&self, tail: u16) {
        // SAFETY: doorbell_addr is valid MMIO address
        mmio_w32(VirtAddr::new(self.doorbell_addr as u64), tail as u32);
    }

    pub fn reset(&self) {
        self.tail.store(0, Ordering::Release);
    }
}

// SAFETY: SubmissionQueue uses DMA-coherent memory and atomic tail pointer for synchronization.
unsafe impl Send for SubmissionQueue {}
unsafe impl Sync for SubmissionQueue {}
