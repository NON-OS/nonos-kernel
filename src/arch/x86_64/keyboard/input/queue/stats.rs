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

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, Default)]
pub struct QueueStats {
    pub total_events: u64,
    pub dropped_events: u64,
    pub priority_drops: u64,
    pub coalesced_events: u64,
    pub peak_size: usize,
    pub current_size: usize,
    pub pressure_warnings: u64,
}

pub(crate) struct QueueStatsAtomic {
    pub total_events: AtomicU64,
    pub dropped_events: AtomicU64,
    pub priority_drops: AtomicU64,
    pub coalesced_events: AtomicU64,
    pub peak_size: AtomicUsize,
    pub pressure_warnings: AtomicU64,
}

impl QueueStatsAtomic {
    pub(crate) const fn new() -> Self {
        Self {
            total_events: AtomicU64::new(0),
            dropped_events: AtomicU64::new(0),
            priority_drops: AtomicU64::new(0),
            coalesced_events: AtomicU64::new(0),
            peak_size: AtomicUsize::new(0),
            pressure_warnings: AtomicU64::new(0),
        }
    }

    pub(crate) fn snapshot(&self, current_size: usize) -> QueueStats {
        QueueStats {
            total_events: self.total_events.load(Ordering::Relaxed),
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
            priority_drops: self.priority_drops.load(Ordering::Relaxed),
            coalesced_events: self.coalesced_events.load(Ordering::Relaxed),
            peak_size: self.peak_size.load(Ordering::Relaxed),
            current_size,
            pressure_warnings: self.pressure_warnings.load(Ordering::Relaxed),
        }
    }
}
