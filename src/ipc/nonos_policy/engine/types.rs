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

pub(super) const MAX_VIOLATIONS: usize = 1000;

pub(super) struct RateLimitTracker {
    pub count: AtomicU64,
    pub window_start_ms: AtomicU64,
}

impl RateLimitTracker {
    pub(super) const fn new() -> Self {
        Self { count: AtomicU64::new(0), window_start_ms: AtomicU64::new(0) }
    }

    pub(super) fn check_and_increment(&self, limit_per_sec: u32) -> bool {
        if limit_per_sec == 0 {
            return true;
        }
        let now_ms = crate::time::timestamp_millis();
        let window_start = self.window_start_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(window_start) >= 1000 {
            self.window_start_ms.store(now_ms, Ordering::Relaxed);
            self.count.store(1, Ordering::Relaxed);
            return true;
        }
        let current = self.count.fetch_add(1, Ordering::Relaxed);
        current < limit_per_sec as u64
    }

    pub(super) fn reset(&self) {
        self.count.store(0, Ordering::Relaxed);
        self.window_start_ms.store(0, Ordering::Relaxed);
    }
}

pub(super) struct PolicyStats {
    pub messages_allowed: AtomicU64,
    pub messages_denied: AtomicU64,
    pub channels_created: AtomicU64,
    pub channels_denied: AtomicU64,
    pub rate_limit_hits: AtomicU64,
}

impl PolicyStats {
    pub(super) const fn new() -> Self {
        Self {
            messages_allowed: AtomicU64::new(0),
            messages_denied: AtomicU64::new(0),
            channels_created: AtomicU64::new(0),
            channels_denied: AtomicU64::new(0),
            rate_limit_hits: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PolicyStatsSnapshot {
    pub messages_allowed: u64,
    pub messages_denied: u64,
    pub channels_created: u64,
    pub channels_denied: u64,
    pub rate_limit_hits: u64,
    pub registered_modules: usize,
    pub recent_violations: usize,
}
