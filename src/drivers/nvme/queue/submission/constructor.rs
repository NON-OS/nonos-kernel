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

use super::super::super::constants::SUBMISSION_ENTRY_SIZE;
use super::super::super::dma::DmaRegion;
use super::super::super::error::NvmeError;
use super::super::super::types::SubmissionEntry;
use super::structure::SubmissionQueue;
use core::ptr::NonNull;
use core::sync::atomic::AtomicU16;

impl SubmissionQueue {
    pub fn new(qid: u16, depth: u16, doorbell_addr: usize) -> Result<Self, NvmeError> {
        if depth == 0 || depth > 4096 {
            return Err(NvmeError::InvalidQueueSize);
        }
        let size = (depth as usize) * SUBMISSION_ENTRY_SIZE;
        let region = DmaRegion::allocate_aligned(size, 4096)?;
        let entries = NonNull::new(region.as_mut_ptr::<SubmissionEntry>())
            .ok_or(NvmeError::SubmissionQueueError)?;
        Ok(Self { region, entries, depth, tail: AtomicU16::new(0), doorbell_addr, qid })
    }
}
