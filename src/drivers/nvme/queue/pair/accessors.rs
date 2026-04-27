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

use super::super::completion::CompletionQueue;
use super::super::submission::SubmissionQueue;
use super::structure::QueuePair;
use core::sync::atomic::Ordering;

impl QueuePair {
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
    pub fn pending_count(&self) -> u16 {
        self.pending_commands.load(Ordering::Acquire)
    }
    pub fn submission_queue(&self) -> &SubmissionQueue {
        &self.sq
    }
    pub fn completion_queue(&self) -> &CompletionQueue {
        &self.cq
    }
    pub fn reset(&self) {
        self.sq.reset();
        self.cq.reset();
        self.pending_commands.store(0, Ordering::Release);
    }
}
