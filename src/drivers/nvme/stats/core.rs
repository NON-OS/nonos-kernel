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

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use super::security::{SecurityStats, SecurityStatsSnapshot};

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
