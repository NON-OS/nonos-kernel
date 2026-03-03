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

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct ConsoleStats {
    pub messages_written: AtomicU64,
    pub bytes_written: AtomicU64,
    pub errors: AtomicU64,
    pub uptime_ticks: AtomicU64,
}

impl ConsoleStats {
    pub const fn new() -> Self {
        Self {
            messages_written: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            uptime_ticks: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn inc_messages(&self) {
        self.messages_written.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_bytes(&self, count: u64) {
        self.bytes_written.fetch_add(count, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ConsoleStatsSnapshot {
        ConsoleStatsSnapshot {
            messages_written: self.messages_written.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            uptime_ticks: self.uptime_ticks.load(Ordering::Relaxed),
        }
    }
}

impl Default for ConsoleStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ConsoleStatsSnapshot {
    pub messages_written: u64,
    pub bytes_written: u64,
    pub errors: u64,
    pub uptime_ticks: u64,
}
