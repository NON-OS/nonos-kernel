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

extern crate alloc;

use alloc::format;
use alloc::string::String;

use crate::log::types::LogLevel;

pub fn format_log_message(level: LogLevel, category: &str, message: &str) -> String {
    format!("[{}] {}: {}\r\n", level.as_str(), category, message)
}

pub fn format_log_message_with_tick(
    tick: u64,
    level: LogLevel,
    category: &str,
    message: &str,
) -> String {
    format!(
        "[{:>8}] [{}] {}: {}\r\n",
        tick,
        level.as_str(),
        category,
        message
    )
}

pub fn format_status(status: &str, message: &str) -> String {
    format!("  [{}] {}\r\n", status, message)
}

pub fn format_ok(message: &str) -> String {
    format!("  [  OK  ] {}\r\n", message)
}

pub fn format_fail(message: &str) -> String {
    format!("  [ FAIL ] {}\r\n", message)
}

pub fn format_skip(message: &str) -> String {
    format!("  [ SKIP ] {}\r\n", message)
}

pub fn format_boot_progress(phase: u8, message: &str) -> String {
    format!("  Phase {}: {}\r\n", phase, message)
}

/// up to 32 bytes
pub fn format_hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes.iter().take(32) {
        let hi = (b >> 4) & 0xF;
        let lo = b & 0xF;
        s.push(if hi < 10 {
            (b'0' + hi) as char
        } else {
            (b'a' + hi - 10) as char
        });
        s.push(if lo < 10 {
            (b'0' + lo) as char
        } else {
            (b'a' + lo - 10) as char
        });
    }
    if bytes.len() > 32 {
        s.push_str("...");
    }
    s
}

pub fn format_hash_short(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(28);
    for &b in &hash[..4] {
        let hi = (b >> 4) & 0xF;
        let lo = b & 0xF;
        s.push(if hi < 10 {
            (b'0' + hi) as char
        } else {
            (b'a' + hi - 10) as char
        });
        s.push(if lo < 10 {
            (b'0' + lo) as char
        } else {
            (b'a' + lo - 10) as char
        });
    }
    s.push_str("...");
    for &b in &hash[28..32] {
        let hi = (b >> 4) & 0xF;
        let lo = b & 0xF;
        s.push(if hi < 10 {
            (b'0' + hi) as char
        } else {
            (b'a' + hi - 10) as char
        });
        s.push(if lo < 10 {
            (b'0' + lo) as char
        } else {
            (b'a' + lo - 10) as char
        });
    }
    s
}

/// human-readable form
pub fn format_memory_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{} GB", bytes / (1024 * 1024 * 1024))
    } else if bytes >= 1024 * 1024 {
        format!("{} MB", bytes / (1024 * 1024))
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} B", bytes)
    }
}
