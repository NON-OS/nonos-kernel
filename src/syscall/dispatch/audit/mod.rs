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

mod entry;
mod name;
mod sink;
mod stats;

pub use entry::{clear_audit_log, get_audit_log, SyscallAuditEntry};
pub use sink::{audit_syscall, set_audit_enabled, set_audit_verbose, AUDIT_ENABLED, AUDIT_VERBOSE};
pub use stats::{get_syscall_stats, SyscallStats, SYSCALL_STATS};
