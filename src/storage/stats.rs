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

pub struct DeviceStatistics {
    pub bytes_read: AtomicU64,
    pub bytes_written: AtomicU64,
    pub read_ops: AtomicU64,
    pub write_ops: AtomicU64,
    pub reads_completed: AtomicU64,
    pub writes_completed: AtomicU64,
    pub errors: AtomicU64,
    pub retries: AtomicU64,
    pub average_read_latency: AtomicU64,
    pub average_write_latency: AtomicU64,
    pub secure_erases_performed: AtomicU64,
    pub last_secure_erase_time: AtomicU64,
}

impl Default for DeviceStatistics {
    fn default() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
            reads_completed: AtomicU64::new(0),
            writes_completed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            average_read_latency: AtomicU64::new(0),
            average_write_latency: AtomicU64::new(0),
            secure_erases_performed: AtomicU64::new(0),
            last_secure_erase_time: AtomicU64::new(0),
        }
    }
}

impl Clone for DeviceStatistics {
    fn clone(&self) -> Self {
        Self {
            bytes_read: AtomicU64::new(self.bytes_read.load(Ordering::Relaxed)),
            bytes_written: AtomicU64::new(self.bytes_written.load(Ordering::Relaxed)),
            read_ops: AtomicU64::new(self.read_ops.load(Ordering::Relaxed)),
            write_ops: AtomicU64::new(self.write_ops.load(Ordering::Relaxed)),
            reads_completed: AtomicU64::new(self.reads_completed.load(Ordering::Relaxed)),
            writes_completed: AtomicU64::new(self.writes_completed.load(Ordering::Relaxed)),
            errors: AtomicU64::new(self.errors.load(Ordering::Relaxed)),
            retries: AtomicU64::new(self.retries.load(Ordering::Relaxed)),
            average_read_latency: AtomicU64::new(self.average_read_latency.load(Ordering::Relaxed)),
            average_write_latency: AtomicU64::new(self.average_write_latency.load(Ordering::Relaxed)),
            secure_erases_performed: AtomicU64::new(self.secure_erases_performed.load(Ordering::Relaxed)),
            last_secure_erase_time: AtomicU64::new(self.last_secure_erase_time.load(Ordering::Relaxed)),
        }
    }
}
