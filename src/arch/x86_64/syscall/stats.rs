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

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct SyscallStats {
    pub total_calls: u64,
    pub total_time_ns: u64,
    pub blocked_calls: u64,
    pub error_count: u64,
    pub hook_detections: u64,
    pub integrity_checks: u64,
    pub last_integrity_check_ns: u64,
    pub security_violations: u64,
}

pub(crate) struct InternalStats {
    pub total_calls: AtomicU64,
    pub total_time_ns: AtomicU64,
    pub blocked_calls: AtomicU64,
    pub error_count: AtomicU64,
    pub hook_detections: AtomicU64,
    pub integrity_checks: AtomicU64,
    pub last_integrity_check_ns: AtomicU64,
    pub security_violations: AtomicU64,
}

impl InternalStats {
    pub(crate) const fn new() -> Self {
        Self {
            total_calls: AtomicU64::new(0),
            total_time_ns: AtomicU64::new(0),
            blocked_calls: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            hook_detections: AtomicU64::new(0),
            integrity_checks: AtomicU64::new(0),
            last_integrity_check_ns: AtomicU64::new(0),
            security_violations: AtomicU64::new(0),
        }
    }

    pub(crate) fn snapshot(&self) -> SyscallStats {
        SyscallStats {
            total_calls: self.total_calls.load(Ordering::Relaxed),
            total_time_ns: self.total_time_ns.load(Ordering::Relaxed),
            blocked_calls: self.blocked_calls.load(Ordering::Relaxed),
            error_count: self.error_count.load(Ordering::Relaxed),
            hook_detections: self.hook_detections.load(Ordering::Relaxed),
            integrity_checks: self.integrity_checks.load(Ordering::Relaxed),
            last_integrity_check_ns: self.last_integrity_check_ns.load(Ordering::Relaxed),
            security_violations: self.security_violations.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyscallRecord {
    pub number: u64,
    pub args: [u64; 6],
    pub return_value: u64,
    pub timestamp_ns: u64,
    pub duration_ns: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub blocked: bool,
}
