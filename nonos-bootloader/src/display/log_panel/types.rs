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

pub const MAX_LOG_LINES: usize = 30;
pub const LOG_LINE_LEN: usize = 58;
pub const LOG_X: u32 = 12;
pub const LOG_Y_START: u32 = 218;
pub const LINE_HEIGHT: u32 = 13;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Ok,
    Warn,
    Error,
    Security,
}

#[derive(Clone, Copy)]
pub struct LogEntry {
    pub text: [u8; LOG_LINE_LEN],
    pub len: usize,
    pub level: LogLevel,
    pub timestamp: u64,
}

impl LogEntry {
    pub const fn empty() -> Self {
        Self {
            text: [0u8; LOG_LINE_LEN],
            len: 0,
            level: LogLevel::Info,
            timestamp: 0,
        }
    }

    pub fn set(&mut self, level: LogLevel, msg: &[u8], timestamp: u64) {
        self.level = level;
        self.timestamp = timestamp;
        self.text = [0u8; LOG_LINE_LEN];
        self.len = msg.len().min(LOG_LINE_LEN);
        self.text[..self.len].copy_from_slice(&msg[..self.len]);
    }
}
