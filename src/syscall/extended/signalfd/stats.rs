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
static TOTAL_READS: AtomicU64 = AtomicU64::new(0);
static TOTAL_SIGNALS_DELIVERED: AtomicU64 = AtomicU64::new(0);
static TOTAL_CLOSED: AtomicU64 = AtomicU64::new(0);

pub fn record_signalfd_created() {
    TOTAL_CREATED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_signalfd_read() {
    TOTAL_READS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_signal_delivered() {
    TOTAL_SIGNALS_DELIVERED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_signalfd_closed() {
    TOTAL_CLOSED.fetch_add(1, Ordering::Relaxed);
}

pub fn get_total_created() -> u64 {
    TOTAL_CREATED.load(Ordering::Relaxed)
}

pub fn get_total_reads() -> u64 {
    TOTAL_READS.load(Ordering::Relaxed)
}

pub fn get_total_signals() -> u64 {
    TOTAL_SIGNALS_DELIVERED.load(Ordering::Relaxed)
}

pub struct SignalfdGlobalStats {
    pub total_created: u64,
    pub total_reads: u64,
    pub total_signals_delivered: u64,
    pub total_closed: u64,
    pub currently_active: u64,
}

pub fn get_global_stats() -> SignalfdGlobalStats {
    SignalfdGlobalStats {
        total_created: TOTAL_CREATED.load(Ordering::Relaxed),
        total_reads: TOTAL_READS.load(Ordering::Relaxed),
        total_signals_delivered: TOTAL_SIGNALS_DELIVERED.load(Ordering::Relaxed),
        total_closed: TOTAL_CLOSED.load(Ordering::Relaxed),
        currently_active: TOTAL_CREATED
            .load(Ordering::Relaxed)
            .saturating_sub(TOTAL_CLOSED.load(Ordering::Relaxed)),
    }
}

pub fn reset_stats() {
    TOTAL_CREATED.store(0, Ordering::Relaxed);
    TOTAL_READS.store(0, Ordering::Relaxed);
    TOTAL_SIGNALS_DELIVERED.store(0, Ordering::Relaxed);
    TOTAL_CLOSED.store(0, Ordering::Relaxed);
}
