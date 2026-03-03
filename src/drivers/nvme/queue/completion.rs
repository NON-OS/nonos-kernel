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

use super::super::constants::{COMPLETION_ENTRY_SIZE, MAX_CID_MISMATCHES};
use super::super::dma::DmaRegion;
use super::super::error::NvmeError;
use super::super::types::CompletionEntry;
use crate::memory::mmio::mmio_w32;

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
        mmio_w32(VirtAddr::new(self.doorbell_addr as u64), head as u32);
    }

    pub fn reset(&self) {
        self.head.store(0, Ordering::Release);
        self.phase.store(1, Ordering::Release);
    }
}

// SAFETY: CompletionQueue uses DMA-coherent memory and atomic head/phase for synchronization.
unsafe impl Send for CompletionQueue {}
unsafe impl Sync for CompletionQueue {}
