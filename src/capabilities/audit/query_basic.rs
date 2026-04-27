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

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::buffer::BUFFER;
use super::constants::MAX_LOG_ENTRIES;
use super::counters::STATS;
use super::entry::AuditEntry;
use super::snapshot::AuditStatsSnapshot;

pub fn get_log() -> Vec<AuditEntry> {
    BUFFER.lock().get_chronological()
}

pub fn get_recent(count: usize) -> Vec<AuditEntry> {
    BUFFER.lock().get_recent(count)
}

pub fn get_stats() -> AuditStatsSnapshot {
    let buf = BUFFER.lock();
    AuditStatsSnapshot {
        total_logged: STATS.total_logged.load(Ordering::Relaxed),
        success_count: STATS.success_count.load(Ordering::Relaxed),
        failure_count: STATS.failure_count.load(Ordering::Relaxed),
        current_entries: buf.len(),
        capacity: MAX_LOG_ENTRIES,
        has_wrapped: buf.has_wrapped(),
    }
}

pub fn reset_stats() {
    STATS.reset();
}
