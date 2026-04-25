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
use super::structure::IoQueue;
use alloc::vec::Vec;

impl IoQueue {
    pub fn submit_and_wait(&self, entry: SubmissionEntry) -> Result<CompletionEntry, NvmeError> {
        self.pair.submit_and_wait(entry)
    }
    pub fn submit(&self, entry: SubmissionEntry) -> Result<u16, NvmeError> {
        self.pair.submit(entry)
    }
    pub fn wait(&self, cid: u16) -> Result<CompletionEntry, NvmeError> {
        self.pair.wait(cid)
    }
    pub fn wait_interrupt(&self, cid: u16) -> Result<CompletionEntry, NvmeError> {
        self.pair.wait_interrupt(cid, self.qid())
    }
    pub fn try_complete(&self) -> Option<CompletionEntry> {
        self.pair.try_complete()
    }
    pub fn try_poll_completion(&self) -> Option<CompletionEntry> {
        self.pair.try_complete()
    }
    pub fn complete_all(&self) -> Vec<CompletionEntry> {
        self.pair.complete_all()
    }
}
