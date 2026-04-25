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

pub mod api;
pub mod core;
pub mod dispatch;
pub mod entry;
pub mod ops;
pub mod state;
pub mod table;
pub mod types;
pub mod validation;

pub use api::{
    configure_security, detect_syscall_hooks, get_recent_calls, get_syscall_stats, init,
    verify_syscall_table_integrity,
};
pub use core::SyscallManager;
pub use state::{is_initialized, SYSCALL_MANAGER};
pub use types::{SyscallHandler, SyscallInfo};

pub mod security {
    pub use crate::arch::x86_64::syscall::security::*;
}
