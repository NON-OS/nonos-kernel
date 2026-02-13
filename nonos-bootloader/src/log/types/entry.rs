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

use super::level::LogLevel;

pub const MAX_MESSAGE_LEN: usize = 256;
pub const MAX_CATEGORY_LEN: usize = 32;

#[derive(Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub tick: u64,
    pub category: [u8; MAX_CATEGORY_LEN],
    pub category_len: u8,
    pub message: [u8; MAX_MESSAGE_LEN],
    pub message_len: u16,
}

impl LogEntry {
    pub const fn new() -> Self {
        Self {
            level: LogLevel::Info,
            tick: 0,
            category: [0u8; MAX_CATEGORY_LEN],
            category_len: 0,
            message: [0u8; MAX_MESSAGE_LEN],
            message_len: 0,
        }
    }

    pub fn create(level: LogLevel, tick: u64, category: &str, message: &str) -> Self {
        let mut entry = Self::new();
        entry.level = level;
        entry.tick = tick;
        // Copy category
        let cat_bytes = category.as_bytes();
        let cat_len = cat_bytes.len().min(MAX_CATEGORY_LEN - 1);
        entry.category[..cat_len].copy_from_slice(&cat_bytes[..cat_len]);
        entry.category_len = cat_len as u8;
        // Copy message
        let msg_bytes = message.as_bytes();
        let msg_len = msg_bytes.len().min(MAX_MESSAGE_LEN - 1);
        entry.message[..msg_len].copy_from_slice(&msg_bytes[..msg_len]);
        entry.message_len = msg_len as u16;

        entry
    }

    pub fn category_str(&self) -> &str {
        let len = self.category_len as usize;
        core::str::from_utf8(&self.category[..len]).unwrap_or("")
    }

    pub fn message_str(&self) -> &str {
        let len = self.message_len as usize;
        core::str::from_utf8(&self.message[..len]).unwrap_or("")
    }

    pub fn is_empty(&self) -> bool {
        self.message_len == 0
    }

    pub fn size(&self) -> usize {
        core::mem::size_of::<Self>()
    }
}

impl Default for LogEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Compact log entry for memory-constrained storage (64 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CompactLogEntry {
    /// Boot tick (8 bytes)
    pub tick: u64,
    /// Level (1 byte)
    pub level: u8,
    /// Category hash (1 byte, truncated)
    pub category_hash: u8,
    /// Message length (2 bytes)
    pub message_len: u16,
    /// Message (52 bytes)
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
        // Simple hash of category
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
