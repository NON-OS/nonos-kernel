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

/// Maximum message length in a log entry
pub const MAX_MESSAGE_LEN: usize = 256;

/// Maximum category length
pub const MAX_CATEGORY_LEN: usize = 32;

/// A single log entry for storage
#[derive(Clone)]
pub struct LogEntry {
    /// Log level
    pub level: LogLevel,
    /// Boot tick when logged (from boot start)
    pub tick: u64,
    /// Category string (null-terminated, max 32 bytes)
    pub category: [u8; MAX_CATEGORY_LEN],
    /// Category length
    pub category_len: u8,
    /// Message string (null-terminated, max 256 bytes)
    pub message: [u8; MAX_MESSAGE_LEN],
    /// Message length
    pub message_len: u16,
}

impl LogEntry {
    /// Create a new empty log entry
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

    /// Create a log entry with data
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

    /// Get category as string slice
    pub fn category_str(&self) -> &str {
        let len = self.category_len as usize;
        core::str::from_utf8(&self.category[..len]).unwrap_or("")
    }

    /// Get message as string slice
    pub fn message_str(&self) -> &str {
        let len = self.message_len as usize;
        core::str::from_utf8(&self.message[..len]).unwrap_or("")
    }

    /// Check if entry is empty/unused
    pub fn is_empty(&self) -> bool {
        self.message_len == 0
    }

    /// Calculate total size of this entry
    pub fn size(&self) -> usize {
        core::mem::size_of::<Self>()
    }
}

impl Default for LogEntry {
    fn default() -> Self {
        Self::new()
    }
}

pub use super::compact::CompactLogEntry;
