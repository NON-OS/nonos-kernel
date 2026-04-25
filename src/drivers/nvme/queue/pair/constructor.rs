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

use super::super::super::constants::DEFAULT_TIMEOUT_SPINS;
use super::super::super::error::NvmeError;
use super::super::completion::CompletionQueue;
use super::super::submission::SubmissionQueue;
use super::structure::QueuePair;
use core::sync::atomic::{AtomicU16, AtomicU32};

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
}
