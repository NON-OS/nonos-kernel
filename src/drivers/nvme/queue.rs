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

use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use x86_64::VirtAddr;
use super::dma::DmaRegion;
use super::types::{SubmissionEntry, CompletionEntry};
use super::constants::{SUBMISSION_ENTRY_SIZE, COMPLETION_ENTRY_SIZE, DEFAULT_TIMEOUT_SPINS, MAX_CID_MISMATCHES};
use super::error::NvmeError;
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
        unsafe {
            mmio_w32(VirtAddr::new(self.doorbell_addr as u64), tail as u32);
        }
    }

    pub fn reset(&self) {
        self.tail.store(0, Ordering::Release);
    }
}

// SAFETY: SubmissionQueue uses DMA-coherent memory and atomic tail pointer for synchronization.
unsafe impl Send for SubmissionQueue {}
unsafe impl Sync for SubmissionQueue {}

pub struct CompletionQueue {
    region: DmaRegion,
    entries: NonNull<CompletionEntry>,
    depth: u16,
    head: AtomicU16,
    phase: AtomicU16,
    doorbell_addr: usize,
    qid: u16,
}

impl CompletionQueue {
    pub fn new(qid: u16, depth: u16, doorbell_addr: usize) -> Result<Self, NvmeError> {
        if depth == 0 || depth > 4096 {
            return Err(NvmeError::InvalidQueueSize);
        }

        let size = (depth as usize) * COMPLETION_ENTRY_SIZE;
        let region = DmaRegion::allocate_aligned(size, 4096)?;
        let entries = NonNull::new(region.as_mut_ptr::<CompletionEntry>())
            .ok_or(NvmeError::CompletionQueueError)?;

        Ok(Self {
            region,
            entries,
            depth,
            head: AtomicU16::new(0),
            phase: AtomicU16::new(1),
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
    pub fn head(&self) -> u16 {
        self.head.load(Ordering::Acquire)
    }

    #[inline]
    pub fn current_phase(&self) -> bool {
        self.phase.load(Ordering::Acquire) == 1
    }

    pub fn poll(&self, expected_cid: u16, timeout_spins: u32) -> Result<CompletionEntry, NvmeError> {
        let mut spins = timeout_spins;
        let mut unexpected_count = 0u32;
        loop {
            let head = self.head.load(Ordering::Acquire);
            let expected_phase = self.phase.load(Ordering::Acquire) == 1;
            let index = (head as usize) % (self.depth as usize);
            // SAFETY: index is within bounds, pointer is valid and aligned
            let entry = unsafe {
                let slot = self.entries.as_ptr().add(index);
                ptr::read_volatile(slot)
            };

            if entry.phase() == expected_phase {
                if entry.cid != expected_cid {
                    unexpected_count += 1;
                    if unexpected_count >= MAX_CID_MISMATCHES {
                        return Err(NvmeError::CqCorruption);
                    }

                    self.advance_head();
                    continue;
                }

                self.advance_head();
                if entry.is_error() {
                    return Err(NvmeError::CommandFailed {
                        status_code: entry.status_field(),
                    });
                }

                return Ok(entry);
            }

            if spins == 0 {
                return Err(NvmeError::CommandTimeout);
            }
            spins -= 1;

            core::hint::spin_loop();
        }
    }

    pub fn try_poll(&self) -> Option<CompletionEntry> {
        let head = self.head.load(Ordering::Acquire);
        let expected_phase = self.phase.load(Ordering::Acquire) == 1;
        let index = (head as usize) % (self.depth as usize);
        // SAFETY: index is within bounds, pointer is valid and aligned
        let entry = unsafe {
            let slot = self.entries.as_ptr().add(index);
            ptr::read_volatile(slot)
        };

        if entry.phase() == expected_phase {
            self.advance_head();
            Some(entry)
        } else {
            None
        }
    }

    pub fn poll_all(&self) -> alloc::vec::Vec<CompletionEntry> {
        let mut entries = alloc::vec::Vec::new();
        while let Some(entry) = self.try_poll() {
            entries.push(entry);
        }

        entries
    }

    fn advance_head(&self) {
        let head = self.head.load(Ordering::Acquire);
        let new_head = head.wrapping_add(1) % self.depth;
        if new_head == 0 {
            let current_phase = self.phase.load(Ordering::Acquire);
            self.phase.store(current_phase ^ 1, Ordering::Release);
        }

        self.head.store(new_head, Ordering::Release);
        self.ring_doorbell(new_head);
    }

    #[inline]
    fn ring_doorbell(&self, head: u16) {
        // SAFETY: doorbell_addr is valid MMIO address
        unsafe {
            mmio_w32(VirtAddr::new(self.doorbell_addr as u64), head as u32);
        }
    }

    pub fn reset(&self) {
        self.head.store(0, Ordering::Release);
        self.phase.store(1, Ordering::Release);
    }
}

// SAFETY: CompletionQueue uses DMA-coherent memory and atomic head/phase for synchronization.
unsafe impl Send for CompletionQueue {}
unsafe impl Sync for CompletionQueue {}

pub struct QueuePair {
    sq: SubmissionQueue,
    cq: CompletionQueue,
    timeout_spins: AtomicU32,
    pending_commands: AtomicU16,
}

impl QueuePair {
    pub fn new(
        qid: u16,
        sq_depth: u16,
        cq_depth: u16,
        sq_doorbell: usize,
        cq_doorbell: usize,
    ) -> Result<Self, NvmeError> {
        let sq = SubmissionQueue::new(qid, sq_depth, sq_doorbell)?;
        let cq = CompletionQueue::new(qid, cq_depth, cq_doorbell)?;

        Ok(Self {
            sq,
            cq,
            timeout_spins: AtomicU32::new(DEFAULT_TIMEOUT_SPINS),
            pending_commands: AtomicU16::new(0),
        })
    }

    #[inline]
    pub const fn qid(&self) -> u16 {
        self.sq.qid()
    }

    #[inline]
    pub fn sq_phys(&self) -> u64 {
        self.sq.phys_addr()
    }

    #[inline]
    pub fn cq_phys(&self) -> u64 {
        self.cq.phys_addr()
    }

    #[inline]
    pub fn sq_depth(&self) -> u16 {
        self.sq.depth()
    }

    #[inline]
    pub fn cq_depth(&self) -> u16 {
        self.cq.depth()
    }

    pub fn set_timeout(&self, spins: u32) {
        self.timeout_spins.store(spins, Ordering::Release);
    }

    pub fn submit_and_wait(&self, entry: SubmissionEntry) -> Result<CompletionEntry, NvmeError> {
        let cid = self.sq.submit(entry)?;
        self.pending_commands.fetch_add(1, Ordering::Relaxed);
        let timeout = self.timeout_spins.load(Ordering::Acquire);
        let result = self.cq.poll(cid, timeout);
        self.pending_commands.fetch_sub(1, Ordering::Relaxed);
        result
    }

    pub fn submit(&self, entry: SubmissionEntry) -> Result<u16, NvmeError> {
        let cid = self.sq.submit(entry)?;
        self.pending_commands.fetch_add(1, Ordering::Relaxed);
        Ok(cid)
    }

    pub fn wait(&self, cid: u16) -> Result<CompletionEntry, NvmeError> {
        let timeout = self.timeout_spins.load(Ordering::Acquire);
        let result = self.cq.poll(cid, timeout);
        self.pending_commands.fetch_sub(1, Ordering::Relaxed);
        result
    }

    pub fn try_complete(&self) -> Option<CompletionEntry> {
        if let Some(entry) = self.cq.try_poll() {
            self.pending_commands.fetch_sub(1, Ordering::Relaxed);
            Some(entry)
        } else {
            None
        }
    }

    pub fn complete_all(&self) -> alloc::vec::Vec<CompletionEntry> {
        let entries = self.cq.poll_all();
        self.pending_commands.fetch_sub(entries.len() as u16, Ordering::Relaxed);
        entries
    }

    pub fn pending_count(&self) -> u16 {
        self.pending_commands.load(Ordering::Acquire)
    }

    pub fn reset(&self) {
        self.sq.reset();
        self.cq.reset();
        self.pending_commands.store(0, Ordering::Release);
    }

    pub fn submission_queue(&self) -> &SubmissionQueue {
        &self.sq
    }

    pub fn completion_queue(&self) -> &CompletionQueue {
        &self.cq
    }
}

// SAFETY: QueuePair wraps Send+Sync queues with atomic pending_commands counter.
unsafe impl Send for QueuePair {}
unsafe impl Sync for QueuePair {}

pub struct AdminQueue {
    pair: QueuePair,
}

impl AdminQueue {
    pub fn new(depth: u16, sq_doorbell: usize, cq_doorbell: usize) -> Result<Self, NvmeError> {
        let pair = QueuePair::new(0, depth, depth, sq_doorbell, cq_doorbell)?;
        Ok(Self { pair })
    }

    #[inline]
    pub fn sq_phys(&self) -> u64 {
        self.pair.sq_phys()
    }

    #[inline]
    pub fn cq_phys(&self) -> u64 {
        self.pair.cq_phys()
    }

    #[inline]
    pub fn depth(&self) -> u16 {
        self.pair.sq_depth()
    }

    pub fn set_timeout(&self, spins: u32) {
        self.pair.set_timeout(spins);
    }

    pub fn submit_and_wait(&self, entry: SubmissionEntry) -> Result<CompletionEntry, NvmeError> {
        self.pair.submit_and_wait(entry)
    }

    pub fn reset(&self) {
        self.pair.reset();
    }
}

// SAFETY: AdminQueue wraps Send+Sync QueuePair.
unsafe impl Send for AdminQueue {}
unsafe impl Sync for AdminQueue {}

pub struct IoQueue {
    pair: QueuePair,
    associated_cq_id: u16,
}

impl IoQueue {
    pub fn new(
        qid: u16,
        sq_depth: u16,
        cq_depth: u16,
        sq_doorbell: usize,
        cq_doorbell: usize,
    ) -> Result<Self, NvmeError> {
        if qid == 0 {
            return Err(NvmeError::InvalidQueueSize);
        }

        let pair = QueuePair::new(qid, sq_depth, cq_depth, sq_doorbell, cq_doorbell)?;

        Ok(Self {
            pair,
            associated_cq_id: qid,
        })
    }

    #[inline]
    pub fn qid(&self) -> u16 {
        self.pair.qid()
    }

    #[inline]
    pub fn cq_id(&self) -> u16 {
        self.associated_cq_id
    }

    #[inline]
    pub fn sq_phys(&self) -> u64 {
        self.pair.sq_phys()
    }

    #[inline]
    pub fn cq_phys(&self) -> u64 {
        self.pair.cq_phys()
    }

    #[inline]
    pub fn sq_depth(&self) -> u16 {
        self.pair.sq_depth()
    }

    #[inline]
    pub fn cq_depth(&self) -> u16 {
        self.pair.cq_depth()
    }

    pub fn set_timeout(&self, spins: u32) {
        self.pair.set_timeout(spins);
    }

    pub fn submit_and_wait(&self, entry: SubmissionEntry) -> Result<CompletionEntry, NvmeError> {
        self.pair.submit_and_wait(entry)
    }

    pub fn submit(&self, entry: SubmissionEntry) -> Result<u16, NvmeError> {
        self.pair.submit(entry)
    }

    pub fn wait(&self, cid: u16) -> Result<CompletionEntry, NvmeError> {
        self.pair.wait(cid)
    }

    pub fn try_complete(&self) -> Option<CompletionEntry> {
        self.pair.try_complete()
    }

    pub fn complete_all(&self) -> alloc::vec::Vec<CompletionEntry> {
        self.pair.complete_all()
    }

    pub fn pending_count(&self) -> u16 {
        self.pair.pending_count()
    }

    pub fn reset(&self) {
        self.pair.reset();
    }
}

// SAFETY: IoQueue wraps Send+Sync QueuePair.
unsafe impl Send for IoQueue {}
unsafe impl Sync for IoQueue {}
