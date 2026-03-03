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
