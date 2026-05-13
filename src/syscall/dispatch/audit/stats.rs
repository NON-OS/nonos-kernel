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

pub static SYSCALL_STATS: SyscallStats = SyscallStats::new();

pub struct SyscallStats {
    pub total_calls: AtomicU64,
    pub successful_calls: AtomicU64,
    pub failed_calls: AtomicU64,
    pub permission_denied: AtomicU64,
    pub audit_entries: AtomicU64,
}

impl SyscallStats {
    pub const fn new() -> Self {
        Self {
            total_calls: AtomicU64::new(0),
            successful_calls: AtomicU64::new(0),
            failed_calls: AtomicU64::new(0),
            permission_denied: AtomicU64::new(0),
            audit_entries: AtomicU64::new(0),
        }
    }
}

pub fn get_syscall_stats() -> (u64, u64, u64, u64) {
    (
        SYSCALL_STATS.total_calls.load(Ordering::Relaxed),
        SYSCALL_STATS.successful_calls.load(Ordering::Relaxed),
        SYSCALL_STATS.failed_calls.load(Ordering::Relaxed),
        SYSCALL_STATS.permission_denied.load(Ordering::Relaxed),
    )
}
