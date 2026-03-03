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

#[derive(Debug)]
pub struct SecurityStats {
    pub rate_limit_hits: AtomicU64,
    pub lba_validation_failures: AtomicU64,
    pub dma_validation_failures: AtomicU64,
    pub cid_mismatches: AtomicU64,
    pub phase_errors: AtomicU64,
    pub command_errors: AtomicU64,
    pub namespace_errors: AtomicU64,
    pub cq_corruption_events: AtomicU64,
}

impl SecurityStats {
    pub const fn new() -> Self {
        Self {
            rate_limit_hits: AtomicU64::new(0),
            lba_validation_failures: AtomicU64::new(0),
            dma_validation_failures: AtomicU64::new(0),
            cid_mismatches: AtomicU64::new(0),
            phase_errors: AtomicU64::new(0),
            command_errors: AtomicU64::new(0),
            namespace_errors: AtomicU64::new(0),
            cq_corruption_events: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn record_rate_limit(&self) {
        self.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_lba_validation_failure(&self) {
        self.lba_validation_failures.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_dma_validation_failure(&self) {
        self.dma_validation_failures.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_cid_mismatch(&self) {
        self.cid_mismatches.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_phase_error(&self) {
        self.phase_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_command_error(&self) {
        self.command_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_namespace_error(&self) {
        self.namespace_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_cq_corruption(&self) {
        self.cq_corruption_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> SecurityStatsSnapshot {
        SecurityStatsSnapshot {
            rate_limit_hits: self.rate_limit_hits.load(Ordering::Relaxed),
            lba_validation_failures: self.lba_validation_failures.load(Ordering::Relaxed),
            dma_validation_failures: self.dma_validation_failures.load(Ordering::Relaxed),
            cid_mismatches: self.cid_mismatches.load(Ordering::Relaxed),
            phase_errors: self.phase_errors.load(Ordering::Relaxed),
            command_errors: self.command_errors.load(Ordering::Relaxed),
            namespace_errors: self.namespace_errors.load(Ordering::Relaxed),
            cq_corruption_events: self.cq_corruption_events.load(Ordering::Relaxed),
        }
    }

    pub fn reset(&self) {
        self.rate_limit_hits.store(0, Ordering::Relaxed);
        self.lba_validation_failures.store(0, Ordering::Relaxed);
        self.dma_validation_failures.store(0, Ordering::Relaxed);
        self.cid_mismatches.store(0, Ordering::Relaxed);
        self.phase_errors.store(0, Ordering::Relaxed);
        self.command_errors.store(0, Ordering::Relaxed);
        self.namespace_errors.store(0, Ordering::Relaxed);
        self.cq_corruption_events.store(0, Ordering::Relaxed);
    }
}

impl Default for SecurityStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct SecurityStatsSnapshot {
    pub rate_limit_hits: u64,
    pub lba_validation_failures: u64,
    pub dma_validation_failures: u64,
    pub cid_mismatches: u64,
    pub phase_errors: u64,
    pub command_errors: u64,
    pub namespace_errors: u64,
    pub cq_corruption_events: u64,
}

impl SecurityStatsSnapshot {
    pub fn total_security_events(&self) -> u64 {
        self.rate_limit_hits
            + self.lba_validation_failures
            + self.dma_validation_failures
            + self.cid_mismatches
            + self.phase_errors
            + self.command_errors
            + self.namespace_errors
            + self.cq_corruption_events
    }

    pub fn has_critical_events(&self) -> bool {
        self.cq_corruption_events > 0 || self.dma_validation_failures > 0
    }
}
