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

use super::security::SecurityStats;
use super::structure::NvmeStats;
use core::sync::atomic::{AtomicU32, AtomicU64};

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
            io_queues: AtomicU32::new(0),
            security: SecurityStats::new(),
        }
    }
}
