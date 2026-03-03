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


use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;
use super::types::{CircuitId, CircuitMetrics};

pub(super) struct PerformanceMonitor {
    pub circuit_stats: Mutex<BTreeMap<CircuitId, CircuitMetrics>>,
    pub global: CircuitGlobalStats,
}

#[derive(Debug, Default)]
pub(super) struct CircuitGlobalStats {
    pub total_circuits_built: AtomicU32,
    pub failed_circuits: AtomicU32,
    pub average_build_time_ms: AtomicU32,
    pub total_data_transferred: AtomicU32,
}

impl PerformanceMonitor {
    pub(super) fn new() -> Self {
        Self {
            circuit_stats: Mutex::new(BTreeMap::new()),
            global: CircuitGlobalStats::default(),
        }
    }

    pub(super) fn record_circuit_built(&self, circuit_id: CircuitId, build_time_ms: u64) {
        self.global.total_circuits_built.fetch_add(1, Ordering::Relaxed);
        let current_avg = self.global.average_build_time_ms.load(Ordering::Relaxed) as u64;
        let total_built = self.global.total_circuits_built.load(Ordering::Relaxed) as u64;
        let new_avg = if total_built == 0 {
            build_time_ms
        } else {
            (current_avg.saturating_mul(total_built.saturating_sub(1)) + build_time_ms) / total_built
        };
        self.global.average_build_time_ms.store(new_avg as u32, Ordering::Relaxed);
        self.circuit_stats.lock().insert(circuit_id, CircuitMetrics {
            total_rtt_ms: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            active_streams: 0,
            uptime_ms: 0,
        });
    }
}
