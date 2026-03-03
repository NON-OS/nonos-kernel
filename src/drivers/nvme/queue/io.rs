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

use super::super::error::NvmeError;
use super::super::types::{CompletionEntry, SubmissionEntry};
use super::pair::QueuePair;

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
