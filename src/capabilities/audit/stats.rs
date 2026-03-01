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

pub struct AuditCounters {
    pub total_logged: AtomicU64,
    pub success_count: AtomicU64,
    pub failure_count: AtomicU64,
}

impl AuditCounters {
    pub const fn new() -> Self {
        Self {
            total_logged: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            failure_count: AtomicU64::new(0),
        }
    }

    pub fn record(&self, success: bool) {
        self.total_logged.fetch_add(1, Ordering::Relaxed);
        if success {
            self.success_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failure_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn reset(&self) {
        self.total_logged.store(0, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
        self.failure_count.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AuditStatsSnapshot {
    pub total_logged: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub current_entries: usize,
    pub capacity: usize,
    pub has_wrapped: bool,
}

impl AuditStatsSnapshot {
    pub fn success_rate(&self) -> f64 {
        if self.total_logged == 0 {
            return 100.0;
        }
        (self.success_count as f64 / self.total_logged as f64) * 100.0
    }

    pub fn failure_rate(&self) -> f64 {
        if self.total_logged == 0 {
            return 0.0;
        }
        (self.failure_count as f64 / self.total_logged as f64) * 100.0
    }

    pub fn buffer_usage_percent(&self) -> f64 {
        if self.capacity == 0 {
            return 0.0;
        }
        (self.current_entries as f64 / self.capacity as f64) * 100.0
    }
}

impl core::fmt::Display for AuditStatsSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Audit[total:{} ok:{} fail:{} buf:{}/{} wrapped:{}]",
            self.total_logged,
            self.success_count,
            self.failure_count,
            self.current_entries,
            self.capacity,
            self.has_wrapped
        )
    }
}

pub static STATS: AuditCounters = AuditCounters::new();
