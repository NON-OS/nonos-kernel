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

extern crate alloc;

use super::super::super::error::NvmeError;
use super::super::super::types::{CompletionEntry, SubmissionEntry};
use super::structure::QueuePair;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

impl QueuePair {
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

    pub fn complete_all(&self) -> Vec<CompletionEntry> {
        let entries = self.cq.poll_all();
        self.pending_commands.fetch_sub(entries.len() as u16, Ordering::Relaxed);
        entries
    }

    pub fn wait_interrupt(&self, cid: u16, qid: u16) -> Result<CompletionEntry, NvmeError> {
        let timeout = self.timeout_spins.load(Ordering::Acquire);
        if !super::super::super::interrupt::wait_for_signal(qid, cid, timeout) {
            return Err(NvmeError::InterruptTimeout);
        }
        self.pending_commands.fetch_sub(1, Ordering::Relaxed);
        self.cq.try_poll().ok_or(NvmeError::CidMismatch)
    }
}
