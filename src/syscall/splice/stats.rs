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

static TOTAL_SPLICE_CALLS: AtomicU64 = AtomicU64::new(0);
static TOTAL_TEE_CALLS: AtomicU64 = AtomicU64::new(0);
static TOTAL_VMSPLICE_CALLS: AtomicU64 = AtomicU64::new(0);
static TOTAL_BYTES_SPLICED: AtomicU64 = AtomicU64::new(0);

pub fn record_splice(bytes: usize) {
    TOTAL_SPLICE_CALLS.fetch_add(1, Ordering::Relaxed);
    TOTAL_BYTES_SPLICED.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub fn record_tee(bytes: usize) {
    TOTAL_TEE_CALLS.fetch_add(1, Ordering::Relaxed);
    TOTAL_BYTES_SPLICED.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub fn record_vmsplice(bytes: usize) {
    TOTAL_VMSPLICE_CALLS.fetch_add(1, Ordering::Relaxed);
    TOTAL_BYTES_SPLICED.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub fn get_total_splice_calls() -> u64 {
    TOTAL_SPLICE_CALLS.load(Ordering::Relaxed)
}

pub fn get_total_tee_calls() -> u64 {
    TOTAL_TEE_CALLS.load(Ordering::Relaxed)
}

pub fn get_total_vmsplice_calls() -> u64 {
    TOTAL_VMSPLICE_CALLS.load(Ordering::Relaxed)
}

pub fn get_total_bytes_spliced() -> u64 {
    TOTAL_BYTES_SPLICED.load(Ordering::Relaxed)
}

pub struct SpliceStats {
    pub splice_calls: u64,
    pub tee_calls: u64,
    pub vmsplice_calls: u64,
    pub total_bytes: u64,
}

pub fn get_stats() -> SpliceStats {
    SpliceStats {
        splice_calls: TOTAL_SPLICE_CALLS.load(Ordering::Relaxed),
        tee_calls: TOTAL_TEE_CALLS.load(Ordering::Relaxed),
        vmsplice_calls: TOTAL_VMSPLICE_CALLS.load(Ordering::Relaxed),
        total_bytes: TOTAL_BYTES_SPLICED.load(Ordering::Relaxed),
    }
}

pub fn reset_stats() {
    TOTAL_SPLICE_CALLS.store(0, Ordering::Relaxed);
    TOTAL_TEE_CALLS.store(0, Ordering::Relaxed);
    TOTAL_VMSPLICE_CALLS.store(0, Ordering::Relaxed);
    TOTAL_BYTES_SPLICED.store(0, Ordering::Relaxed);
}
