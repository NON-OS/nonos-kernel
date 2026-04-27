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

use super::structure::NvmeStats;
use core::sync::atomic::Ordering;

impl NvmeStats {
    #[inline]
    pub fn set_io_queue_count(&self, count: u32) {
        self.io_queues.store(count, Ordering::Relaxed);
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
}
