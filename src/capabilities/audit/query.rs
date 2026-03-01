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

use crate::capabilities::types::Capability;

use super::buffer::BUFFER;
use super::constants::MAX_LOG_ENTRIES;
use super::entry::AuditEntry;
use super::stats::{AuditStatsSnapshot, STATS};

pub fn get_log() -> Vec<AuditEntry> {
    BUFFER.lock().get_chronological()
}

pub fn get_recent(count: usize) -> Vec<AuditEntry> {
    BUFFER.lock().get_recent(count)
}

pub fn get_by_module(module_id: u64) -> Vec<AuditEntry> {
    BUFFER
        .lock()
        .get_chronological()
        .into_iter()
        .filter(|e| e.matches_module(module_id))
        .collect()
}

pub fn get_by_action(action: &str) -> Vec<AuditEntry> {
    BUFFER
        .lock()
        .get_chronological()
        .into_iter()
        .filter(|e| e.matches_action(action))
        .collect()
}

pub fn get_by_time_range(start_ms: u64, end_ms: u64) -> Vec<AuditEntry> {
    BUFFER
        .lock()
        .get_chronological()
        .into_iter()
        .filter(|e| e.in_time_range(start_ms, end_ms))
        .collect()
}

pub fn get_failures() -> Vec<AuditEntry> {
    BUFFER
        .lock()
        .get_chronological()
        .into_iter()
        .filter(|e| !e.success)
        .collect()
}

pub fn get_successes() -> Vec<AuditEntry> {
    BUFFER
        .lock()
        .get_chronological()
        .into_iter()
        .filter(|e| e.success)
        .collect()
}

pub fn get_by_capability(cap: Capability) -> Vec<AuditEntry> {
    BUFFER
        .lock()
        .get_chronological()
        .into_iter()
        .filter(|e| e.matches_capability(cap))
        .collect()
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
