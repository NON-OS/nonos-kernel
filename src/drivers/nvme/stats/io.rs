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

pub struct IoStats {
    pub iops_read: AtomicU64,
    pub iops_write: AtomicU64,
    pub latency_sum_ns: AtomicU64,
    pub latency_count: AtomicU64,
    pub max_latency_ns: AtomicU64,
    pub min_latency_ns: AtomicU64,
}

impl IoStats {
    pub const fn new() -> Self {
        Self {
            iops_read: AtomicU64::new(0),
            iops_write: AtomicU64::new(0),
            latency_sum_ns: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            max_latency_ns: AtomicU64::new(0),
            min_latency_ns: AtomicU64::new(u64::MAX),
        }
    }

    #[inline]
    pub fn record_read_iop(&self) {
        self.iops_read.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_write_iop(&self) {
        self.iops_write.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_latency(&self, latency_ns: u64) {
        self.latency_sum_ns.fetch_add(latency_ns, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);

        let mut max = self.max_latency_ns.load(Ordering::Relaxed);
        while latency_ns > max {
            match self.max_latency_ns.compare_exchange_weak(
                max,
                latency_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => max = current,
            }
        }

        let mut min = self.min_latency_ns.load(Ordering::Relaxed);
        while latency_ns < min {
            match self.min_latency_ns.compare_exchange_weak(
                min,
                latency_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => min = current,
            }
        }
    }

    pub fn average_latency_ns(&self) -> u64 {
        let count = self.latency_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0;
        }
        self.latency_sum_ns.load(Ordering::Relaxed) / count
    }

    pub fn reset(&self) {
        self.iops_read.store(0, Ordering::Relaxed);
        self.iops_write.store(0, Ordering::Relaxed);
        self.latency_sum_ns.store(0, Ordering::Relaxed);
        self.latency_count.store(0, Ordering::Relaxed);
        self.max_latency_ns.store(0, Ordering::Relaxed);
        self.min_latency_ns.store(u64::MAX, Ordering::Relaxed);
    }
}

impl Default for IoStats {
    fn default() -> Self {
        Self::new()
    }
}
