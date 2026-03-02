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
pub mod backend;
pub mod manager;
mod helpers;
mod macros;
mod compat;

pub use types::{Severity, LogEntry};
pub use backend::{LogBackend, VgaBackend, RamBufferBackend, RAM_BUF_SIZE};
pub use manager::{
    LogManager, LOGGER, PANIC_MODE,
    init, log, enter_panic_mode, log_critical, try_get_logger,
    get_log_entries, get_recent_logs, log_entry_count, clear_log_buffer,
};
pub use helpers::{debug_simple, info_simple, warn_simple, log_error_simple};

pub use init as init_logger;

pub use crate::info;
pub use crate::log_info;
pub use crate::log_warn;
pub use crate::log_err;
pub use crate::log_dbg;
pub use crate::log_fatal;
pub use crate::log_error;
pub use crate::log_debug;
pub use crate::log_warning;
pub use crate::debug;
pub use crate::error;
pub use crate::security_log;
pub use crate::warn;

pub use compat::logger;
pub use compat::nonos_logger;
pub use compat::simple_logger;
