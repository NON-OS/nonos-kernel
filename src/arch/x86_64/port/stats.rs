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

pub struct PortStats {
    pub bytes_read: AtomicU64,
    pub bytes_written: AtomicU64,
    pub read_ops: AtomicU64,
    pub write_ops: AtomicU64,
    pub string_read_ops: AtomicU64,
    pub string_write_ops: AtomicU64,
    pub io_delays: AtomicU64,
}

impl PortStats {
    pub const fn new() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
            string_read_ops: AtomicU64::new(0),
            string_write_ops: AtomicU64::new(0),
            io_delays: AtomicU64::new(0),
        }
    }

    pub fn reset(&self) {
        self.bytes_read.store(0, Ordering::SeqCst);
        self.bytes_written.store(0, Ordering::SeqCst);
        self.read_ops.store(0, Ordering::SeqCst);
        self.write_ops.store(0, Ordering::SeqCst);
        self.string_read_ops.store(0, Ordering::SeqCst);
        self.string_write_ops.store(0, Ordering::SeqCst);
        self.io_delays.store(0, Ordering::SeqCst);
    }

    pub fn snapshot(&self) -> PortStatsSnapshot {
        PortStatsSnapshot {
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            read_ops: self.read_ops.load(Ordering::Relaxed),
            write_ops: self.write_ops.load(Ordering::Relaxed),
            string_read_ops: self.string_read_ops.load(Ordering::Relaxed),
            string_write_ops: self.string_write_ops.load(Ordering::Relaxed),
            io_delays: self.io_delays.load(Ordering::Relaxed),
        }
    }

    pub fn total_ops(&self) -> u64 {
        self.read_ops.load(Ordering::Relaxed)
            + self.write_ops.load(Ordering::Relaxed)
            + self.string_read_ops.load(Ordering::Relaxed)
            + self.string_write_ops.load(Ordering::Relaxed)
    }
}

impl Default for PortStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PortStatsSnapshot {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub string_read_ops: u64,
    pub string_write_ops: u64,
    pub io_delays: u64,
}

impl PortStatsSnapshot {
    pub const fn total_ops(&self) -> u64 {
        self.read_ops + self.write_ops + self.string_read_ops + self.string_write_ops
    }

    pub const fn total_bytes(&self) -> u64 {
        self.bytes_read + self.bytes_written
    }
}

pub static PORT_STATS: PortStats = PortStats::new();

pub fn stats() -> &'static PortStats {
    &PORT_STATS
}

pub fn get_snapshot() -> PortStatsSnapshot {
    PORT_STATS.snapshot()
}

pub fn reset_stats() {
    PORT_STATS.reset();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_stats_new() {
        let stats = PortStats::new();
        assert_eq!(stats.read_ops.load(Ordering::SeqCst), 0);
        assert_eq!(stats.write_ops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_port_stats_reset() {
        let stats = PortStats::new();
        stats.read_ops.fetch_add(5, Ordering::SeqCst);
        stats.write_ops.fetch_add(3, Ordering::SeqCst);

        stats.reset();
        assert_eq!(stats.read_ops.load(Ordering::SeqCst), 0);
        assert_eq!(stats.write_ops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_snapshot_totals() {
        let snapshot = PortStatsSnapshot {
            bytes_read: 100,
            bytes_written: 200,
            read_ops: 10,
            write_ops: 20,
            string_read_ops: 5,
            string_write_ops: 3,
            io_delays: 2,
        };

        assert_eq!(snapshot.total_ops(), 38);
        assert_eq!(snapshot.total_bytes(), 300);
    }
}
