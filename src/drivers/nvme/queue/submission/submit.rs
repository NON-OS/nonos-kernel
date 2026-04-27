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
use super::super::super::types::SubmissionEntry;
use super::structure::SubmissionQueue;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{fence, Ordering};

impl SubmissionQueue {
    pub fn submit(&self, mut entry: SubmissionEntry) -> Result<u16, NvmeError> {
        let tail = self.tail.load(Ordering::Acquire);
        let cid = tail;
        entry.set_cid(cid);
        entry.sanitize();
        let index = (tail as usize) % (self.depth as usize);
        unsafe {
            ptr::write_volatile(self.entries.as_ptr().add(index), entry);
        }
        let new_tail = tail.wrapping_add(1) % self.depth;
        self.tail.store(new_tail, Ordering::Release);
        fence(Ordering::SeqCst);
        self.ring_doorbell(new_tail);
        Ok(cid)
    }

    pub fn submit_batch(&self, entries: &[SubmissionEntry]) -> Result<Vec<u16>, NvmeError> {
        let mut cids = Vec::with_capacity(entries.len());
        let mut tail = self.tail.load(Ordering::Acquire);
        for entry in entries {
            let cid = tail;
            let mut cmd = *entry;
            cmd.set_cid(cid);
            cmd.sanitize();
            let index = (tail as usize) % (self.depth as usize);
            unsafe {
                ptr::write_volatile(self.entries.as_ptr().add(index), cmd);
            }
            cids.push(cid);
            tail = tail.wrapping_add(1) % self.depth;
        }
        self.tail.store(tail, Ordering::Release);
        fence(Ordering::SeqCst);
        self.ring_doorbell(tail);
        Ok(cids)
    }
}
