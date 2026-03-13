// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::entry::LogEntry;
use super::level::LogLevel;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CompactLogEntry {
    pub tick: u64,
    pub level: u8,
    pub category_hash: u8,
    pub message_len: u16,
    pub message: [u8; 52],
}

impl CompactLogEntry {
    pub const fn new() -> Self {
        Self {
            tick: 0,
            level: LogLevel::Info as u8,
            category_hash: 0,
            message_len: 0,
            message: [0u8; 52],
        }
    }

    pub fn from_entry(entry: &LogEntry) -> Self {
        let mut compact = Self::new();
        compact.tick = entry.tick;
        compact.level = entry.level as u8;

        let mut hash = 0u8;
        for &b in &entry.category[..entry.category_len as usize] {
            hash = hash.wrapping_add(b);
        }
        compact.category_hash = hash;

        let msg_len = (entry.message_len as usize).min(52);
        compact.message[..msg_len].copy_from_slice(&entry.message[..msg_len]);
        compact.message_len = msg_len as u16;

        compact
    }

    pub fn log_level(&self) -> LogLevel {
        LogLevel::from_u8(self.level).unwrap_or(LogLevel::Info)
    }

    pub fn message_str(&self) -> &str {
        let len = (self.message_len as usize).min(52);
        core::str::from_utf8(&self.message[..len]).unwrap_or("")
    }
}

impl Default for CompactLogEntry {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<CompactLogEntry>() == 64);
