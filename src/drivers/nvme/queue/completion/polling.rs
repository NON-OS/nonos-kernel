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

use super::super::super::constants::MAX_CID_MISMATCHES;
use super::super::super::error::NvmeError;
use super::super::super::types::CompletionEntry;
use super::structure::CompletionQueue;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::Ordering;

impl CompletionQueue {
    pub fn poll(
        &self,
        expected_cid: u16,
        timeout_spins: u32,
    ) -> Result<CompletionEntry, NvmeError> {
        let mut spins = timeout_spins;
        let mut unexpected_count = 0u32;
        loop {
            let head = self.head.load(Ordering::Acquire);
            let expected_phase = self.phase.load(Ordering::Acquire) == 1;
            let index = (head as usize) % (self.depth as usize);
            let entry: CompletionEntry =
                unsafe { ptr::read_volatile(self.entries.as_ptr().add(index)) };
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
                    return Err(NvmeError::CommandFailed { status_code: entry.status_field() });
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
        let entry: CompletionEntry =
            unsafe { ptr::read_volatile(self.entries.as_ptr().add(index)) };
        if entry.phase() == expected_phase {
            self.advance_head();
            Some(entry)
        } else {
            None
        }
    }

    pub fn poll_all(&self) -> Vec<CompletionEntry> {
        let mut entries = Vec::new();
        while let Some(entry) = self.try_poll() {
            entries.push(entry);
        }
        entries
    }
}
