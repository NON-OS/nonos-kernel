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

pub mod error;
pub mod handlers;
pub mod manager;
pub mod msr;
pub mod numbers;
pub mod security;
pub mod stats;
pub mod util;

pub use error::SyscallError;
pub use manager::{
    configure_security, detect_syscall_hooks, get_recent_calls, get_syscall_stats, init,
    is_initialized, verify_syscall_table_integrity, SyscallHandler, SyscallInfo, SyscallManager,
};
pub use numbers as syscall_numbers;
pub use security::SecurityConfig;
pub use stats::{SyscallRecord, SyscallStats};
