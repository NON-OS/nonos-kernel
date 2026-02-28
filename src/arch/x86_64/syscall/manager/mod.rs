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

pub mod types;
pub mod core;
pub mod table;
pub mod validation;
pub mod dispatch;
pub mod ops;
pub mod entry;
pub mod state;
pub mod api;

pub use types::{SyscallHandler, SyscallInfo};
pub use core::SyscallManager;
pub use state::{SYSCALL_MANAGER, is_initialized};
pub use api::{init, configure_security, detect_syscall_hooks, get_recent_calls, get_syscall_stats, verify_syscall_table_integrity};

pub mod security {
    pub use crate::arch::x86_64::syscall::security::*;
}
