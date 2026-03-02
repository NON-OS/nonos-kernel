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

pub mod logger {
    pub use crate::log::{
        log, init, enter_panic_mode, log_critical, try_get_logger,
        Severity, LogManager,
    };
    pub use crate::{info, log_info, log_warn, log_err, log_dbg, log_fatal, log_error, log_debug, log_warning, warn, debug};
}

pub mod nonos_logger {
    pub use crate::log::{
        Severity, LogEntry, LogBackend, VgaBackend, RamBufferBackend, RAM_BUF_SIZE,
        LogManager, LOGGER, PANIC_MODE, init, log, enter_panic_mode, log_critical,
        try_get_logger, init_logger, debug,
        get_log_entries, get_recent_logs, log_entry_count, clear_log_buffer,
    };
}

pub mod simple_logger {
    pub use super::nonos_logger::*;
}
