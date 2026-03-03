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

use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use super::super::constants::DEFAULT_TIMEOUT_SPINS;
use super::super::error::NvmeError;
use super::super::types::{CompletionEntry, SubmissionEntry};
use super::completion::CompletionQueue;
use super::submission::SubmissionQueue;

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
