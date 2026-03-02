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

use crate::log::types::LogEntry;
use super::traits::LogBackend;

pub const RAM_BUF_SIZE: usize = 1024;

pub struct RamBufferBackend {
    buf: [Option<LogEntry>; RAM_BUF_SIZE],
    head: usize,
}

impl RamBufferBackend {
    pub const fn new() -> Self {
        const NONE: Option<LogEntry> = None;
        Self { buf: [NONE; RAM_BUF_SIZE], head: 0 }
    }

    pub fn get_entries(&self) -> alloc::vec::Vec<LogEntry> {
        let mut entries = alloc::vec::Vec::with_capacity(RAM_BUF_SIZE);

        for i in 0..RAM_BUF_SIZE {
            let idx = (self.head + i) % RAM_BUF_SIZE;
            if let Some(ref entry) = self.buf[idx] {
                entries.push(entry.clone());
            }
        }

        entries
    }

    pub fn get_recent(&self, count: usize) -> alloc::vec::Vec<LogEntry> {
        let mut entries = alloc::vec::Vec::with_capacity(count.min(RAM_BUF_SIZE));

        for i in 0..RAM_BUF_SIZE {
            let idx = (self.head + RAM_BUF_SIZE - 1 - i) % RAM_BUF_SIZE;
            if let Some(ref entry) = self.buf[idx] {
                entries.push(entry.clone());
                if entries.len() >= count {
                    break;
                }
            }
        }

        entries.reverse();
        entries
    }

    pub fn entry_count(&self) -> usize {
        self.buf.iter().filter(|e| e.is_some()).count()
    }

    pub fn clear(&mut self) {
        for entry in &mut self.buf {
            *entry = None;
        }
        self.head = 0;
    }
}

impl LogBackend for RamBufferBackend {
    fn write(&mut self, entry: &LogEntry) {
        self.buf[self.head] = Some(LogEntry {
            ts: entry.ts,
            cpu: entry.cpu,
            sev: entry.sev,
            msg: entry.msg.clone(),
            hash: entry.hash,
        });
        self.head = (self.head + 1) % RAM_BUF_SIZE;
    }
}
