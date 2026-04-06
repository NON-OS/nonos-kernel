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

static TOTAL_CREATED: AtomicU64 = AtomicU64::new(0);
static TOTAL_ARMED: AtomicU64 = AtomicU64::new(0);
static TOTAL_DISARMED: AtomicU64 = AtomicU64::new(0);
static TOTAL_EXPIRATIONS: AtomicU64 = AtomicU64::new(0);
static TOTAL_READS: AtomicU64 = AtomicU64::new(0);

pub fn record_timerfd_created() {
    TOTAL_CREATED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_timerfd_armed() {
    TOTAL_ARMED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_timerfd_disarmed() {
    TOTAL_DISARMED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_timerfd_expiration() {
    TOTAL_EXPIRATIONS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_timerfd_read() {
    TOTAL_READS.fetch_add(1, Ordering::Relaxed);
}

pub fn get_total_created() -> u64 {
    TOTAL_CREATED.load(Ordering::Relaxed)
}

pub fn get_total_armed() -> u64 {
    TOTAL_ARMED.load(Ordering::Relaxed)
}

pub fn get_total_expirations() -> u64 {
    TOTAL_EXPIRATIONS.load(Ordering::Relaxed)
}

pub struct TimerfdGlobalStats {
    pub total_created: u64,
    pub total_armed: u64,
    pub total_disarmed: u64,
    pub total_expirations: u64,
    pub total_reads: u64,
}

pub fn get_global_stats() -> TimerfdGlobalStats {
    TimerfdGlobalStats {
        total_created: TOTAL_CREATED.load(Ordering::Relaxed),
        total_armed: TOTAL_ARMED.load(Ordering::Relaxed),
        total_disarmed: TOTAL_DISARMED.load(Ordering::Relaxed),
        total_expirations: TOTAL_EXPIRATIONS.load(Ordering::Relaxed),
        total_reads: TOTAL_READS.load(Ordering::Relaxed),
    }
}

pub fn reset_stats() {
    TOTAL_CREATED.store(0, Ordering::Relaxed);
    TOTAL_ARMED.store(0, Ordering::Relaxed);
    TOTAL_DISARMED.store(0, Ordering::Relaxed);
    TOTAL_EXPIRATIONS.store(0, Ordering::Relaxed);
    TOTAL_READS.store(0, Ordering::Relaxed);
}
