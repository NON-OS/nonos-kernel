// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};
#[derive(Debug)]
pub struct NvmeStats {
    pub commands_submitted: AtomicU64,
    pub commands_completed: AtomicU64,
    pub read_commands: AtomicU64,
    pub write_commands: AtomicU64,
    pub admin_commands: AtomicU64,
    pub bytes_read: AtomicU64,
    pub bytes_written: AtomicU64,
    pub errors: AtomicU64,
    pub timeouts: AtomicU64,
    pub namespaces: AtomicU32,
    pub security: SecurityStats,
}

impl NvmeStats {
    pub const fn new() -> Self {
        Self {
            commands_submitted: AtomicU64::new(0),
            commands_completed: AtomicU64::new(0),
            read_commands: AtomicU64::new(0),
            write_commands: AtomicU64::new(0),
            admin_commands: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            namespaces: AtomicU32::new(0),
            security: SecurityStats::new(),
        }
    }

    #[inline]
    pub fn record_submit(&self) {
        self.commands_submitted.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_complete(&self) {
        self.commands_completed.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_read(&self, bytes: u64) {
        self.read_commands.fetch_add(1, Ordering::Relaxed);
        self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_write(&self, bytes: u64) {
        self.write_commands.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_admin(&self) {
        self.admin_commands.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn set_namespace_count(&self, count: u32) {
        self.namespaces.store(count, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> NvmeStatsSnapshot {
        NvmeStatsSnapshot {
            commands_submitted: self.commands_submitted.load(Ordering::Relaxed),
            commands_completed: self.commands_completed.load(Ordering::Relaxed),
            read_commands: self.read_commands.load(Ordering::Relaxed),
            write_commands: self.write_commands.load(Ordering::Relaxed),
            admin_commands: self.admin_commands.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            namespaces: self.namespaces.load(Ordering::Relaxed),
            security: self.security.snapshot(),
        }
    }

    pub fn reset(&self) {
        self.commands_submitted.store(0, Ordering::Relaxed);
        self.commands_completed.store(0, Ordering::Relaxed);
        self.read_commands.store(0, Ordering::Relaxed);
        self.write_commands.store(0, Ordering::Relaxed);
        self.admin_commands.store(0, Ordering::Relaxed);
        self.bytes_read.store(0, Ordering::Relaxed);
        self.bytes_written.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        self.timeouts.store(0, Ordering::Relaxed);
        self.security.reset();
    }
}

impl Default for NvmeStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct NvmeStatsSnapshot {
    pub commands_submitted: u64,
    pub commands_completed: u64,
    pub read_commands: u64,
    pub write_commands: u64,
    pub admin_commands: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub errors: u64,
    pub timeouts: u64,
    pub namespaces: u32,
    pub security: SecurityStatsSnapshot,
}

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
