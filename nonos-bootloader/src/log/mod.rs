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

pub mod buffer;
pub mod global;
mod init;
pub mod output;
pub mod storage;
pub mod types;

// Backward-compatible logger API
pub mod logger {
    pub use super::global::init_global_state as init_logger;
    pub use super::output::{
        log_critical, log_critical_st, log_debug, log_debug_st, log_error, log_error_st, log_info,
        log_info_st, log_warn, log_warn_st,
    };
    pub use super::types::LogLevel;
}

pub use types::{
    CompactLogEntry, LogCategory, LogEntry, LogLevel, MAX_CATEGORY_LEN, MAX_MESSAGE_LEN,
};

pub use buffer::{
    format_boot_progress, format_fail, format_hash_short, format_hex_bytes, format_log_line,
    format_log_line_with_tick, format_log_message, format_log_message_with_tick,
    format_memory_size, format_ok, format_skip, format_status, utf8_to_utf16, Utf16Buffer,
    UTF16_BUFFER_SIZE,
};

pub use global::{
    get_boot_services, get_boot_tick, get_log_count, get_min_level, get_system_table,
    increment_log_count, init_global_state, is_initialized, reset_log_count, set_min_level,
    should_log, shutdown_global_state,
};

pub use output::{
    clear_console_st, log_at_level, log_at_level_st, log_critical, log_critical_st, log_debug,
    log_debug_st, log_error, log_error_st, log_fatal, log_fatal_st, log_info, log_info_st,
    log_trace, log_trace_st, log_warn, log_warn_st, set_cursor_st, set_cursor_visible_st,
    write_buffer_st, write_log_global, write_log_st, write_newline_st, write_raw_st,
};

pub use storage::{
    boot_log_count, boot_log_overflow, clear_boot_log, critical_count, disable_boot_log,
    enable_boot_log, error_count, get_boot_log_stats, get_entries_by_level, get_last_entries,
    has_critical_errors, has_errors, is_boot_log_enabled, store_boot_log, store_boot_message,
    warn_count, BootLogStats, LogRingBuffer, LogRingIterator, BOOT_LOG_CAPACITY,
    DEFAULT_RING_CAPACITY,
};

pub use init::{init_logging, shutdown_logging};
