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
use core::sync::atomic::{AtomicU32, AtomicU64};

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
    pub io_queues: AtomicU32,
    pub security: SecurityStats,
}

impl Default for NvmeStats {
    fn default() -> Self {
        Self::new()
    }
}
