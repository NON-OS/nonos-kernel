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

use core::sync::atomic::{AtomicBool, Ordering};

use crate::syscall::{SyscallNumber, SyscallResult};

use super::entry::{SyscallAuditEntry, AUDIT_LOG};
use super::name::syscall_name;
use super::stats::SYSCALL_STATS;

pub static AUDIT_ENABLED: AtomicBool = AtomicBool::new(true);
pub static AUDIT_VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn audit_syscall(syscall: SyscallNumber, args: [u64; 4], result: &SyscallResult) {
    if !AUDIT_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let name = syscall_name(syscall);
    let pid = crate::process::current_process().map(|p| p.pid).unwrap_or(0);
    let entry = SyscallAuditEntry {
        timestamp_ms: crate::time::timestamp_millis(),
        syscall_num: syscall as u64,
        syscall_name: name,
        pid,
        result: result.value,
        args,
        success: result.value >= 0,
    };
    if AUDIT_VERBOSE.load(Ordering::Relaxed) {
        crate::log::info!(
            "syscall: {}({:x},{:x},{:x},{:x}) = {} [pid={}]",
            name,
            args[0],
            args[1],
            args[2],
            args[3],
            result.value,
            pid
        );
    }
    let mut log = AUDIT_LOG.lock();
    log.push(entry);
    SYSCALL_STATS.audit_entries.fetch_add(1, Ordering::Relaxed);
}

pub fn set_audit_enabled(enabled: bool) {
    AUDIT_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn set_audit_verbose(verbose: bool) {
    AUDIT_VERBOSE.store(verbose, Ordering::Relaxed);
}
