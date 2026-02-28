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

extern crate alloc;

use alloc::vec::Vec;

use crate::arch::x86_64::syscall::error::SyscallError;
use crate::arch::x86_64::syscall::security::SecurityConfig;
use crate::arch::x86_64::syscall::stats::{SyscallStats, SyscallRecord};
use super::state::SYSCALL_MANAGER;

pub fn init() -> Result<(), SyscallError> {
    SYSCALL_MANAGER.init()
}

pub fn configure_security(config: SecurityConfig) {
    SYSCALL_MANAGER.configure(config);
}

pub fn detect_syscall_hooks() -> bool {
    SYSCALL_MANAGER.detect_hooks()
}

pub fn get_recent_calls() -> Vec<SyscallRecord> {
    SYSCALL_MANAGER.get_audit_log()
}

pub fn get_syscall_stats() -> SyscallStats {
    SYSCALL_MANAGER.get_statistics()
}

pub fn verify_syscall_table_integrity() -> bool {
    SYSCALL_MANAGER.verify_integrity()
}
