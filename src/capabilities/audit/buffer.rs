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

use alloc::vec::Vec;
use spin::Mutex;

use super::constants::MAX_LOG_ENTRIES;
use super::entry::AuditEntry;

pub struct AuditBuffer {
    entries: Vec<AuditEntry>,
    write_pos: usize,
    wrapped: bool,
}

impl AuditBuffer {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            write_pos: 0,
            wrapped: false,
        }
    }

    pub fn push(&mut self, entry: AuditEntry) {
        if self.entries.len() < MAX_LOG_ENTRIES {
            self.entries.push(entry);
            self.write_pos = self.entries.len();
        } else {
            let pos = self.write_pos % MAX_LOG_ENTRIES;
            self.entries[pos] = entry;
            self.write_pos = pos + 1;
            self.wrapped = true;
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get_chronological(&self) -> Vec<AuditEntry> {
        if !self.wrapped {
            self.entries.clone()
        } else {
            let pos = self.write_pos % MAX_LOG_ENTRIES;
            let mut result = Vec::with_capacity(self.entries.len());
            result.extend_from_slice(&self.entries[pos..]);
            result.extend_from_slice(&self.entries[..pos]);
            result
        }
    }

    pub fn get_recent(&self, count: usize) -> Vec<AuditEntry> {
        let all = self.get_chronological();
        let start = all.len().saturating_sub(count);
        all[start..].to_vec()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.write_pos = 0;
        self.wrapped = false;
    }

    pub fn has_wrapped(&self) -> bool {
        self.wrapped
    }
}

pub static BUFFER: Mutex<AuditBuffer> = Mutex::new(AuditBuffer::new());
