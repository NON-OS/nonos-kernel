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

static TOTAL_CONTEXTS_CREATED: AtomicU64 = AtomicU64::new(0);
static TOTAL_OPERATIONS_SUBMITTED: AtomicU64 = AtomicU64::new(0);
static TOTAL_OPERATIONS_COMPLETED: AtomicU64 = AtomicU64::new(0);
static TOTAL_OPERATIONS_CANCELLED: AtomicU64 = AtomicU64::new(0);

pub fn record_context_created() {
    TOTAL_CONTEXTS_CREATED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_operation_submitted(count: usize) {
    TOTAL_OPERATIONS_SUBMITTED.fetch_add(count as u64, Ordering::Relaxed);
}

pub fn record_operation_completed(count: usize) {
    TOTAL_OPERATIONS_COMPLETED.fetch_add(count as u64, Ordering::Relaxed);
}

pub fn record_operation_cancelled(count: usize) {
    TOTAL_OPERATIONS_CANCELLED.fetch_add(count as u64, Ordering::Relaxed);
}

pub fn get_total_contexts() -> u64 {
    TOTAL_CONTEXTS_CREATED.load(Ordering::Relaxed)
}

pub fn get_total_submitted() -> u64 {
    TOTAL_OPERATIONS_SUBMITTED.load(Ordering::Relaxed)
}

pub fn get_total_completed() -> u64 {
    TOTAL_OPERATIONS_COMPLETED.load(Ordering::Relaxed)
}

pub fn get_total_cancelled() -> u64 {
    TOTAL_OPERATIONS_CANCELLED.load(Ordering::Relaxed)
}

pub struct AioStats {
    pub contexts_created: u64,
    pub operations_submitted: u64,
    pub operations_completed: u64,
    pub operations_cancelled: u64,
}

pub fn get_stats() -> AioStats {
    AioStats {
        contexts_created: TOTAL_CONTEXTS_CREATED.load(Ordering::Relaxed),
        operations_submitted: TOTAL_OPERATIONS_SUBMITTED.load(Ordering::Relaxed),
        operations_completed: TOTAL_OPERATIONS_COMPLETED.load(Ordering::Relaxed),
        operations_cancelled: TOTAL_OPERATIONS_CANCELLED.load(Ordering::Relaxed),
    }
}

pub fn reset_stats() {
    TOTAL_CONTEXTS_CREATED.store(0, Ordering::Relaxed);
    TOTAL_OPERATIONS_SUBMITTED.store(0, Ordering::Relaxed);
    TOTAL_OPERATIONS_COMPLETED.store(0, Ordering::Relaxed);
    TOTAL_OPERATIONS_CANCELLED.store(0, Ordering::Relaxed);
}
