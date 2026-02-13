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

mod boot_log;
mod ring;

pub use boot_log::{
    boot_log_count, boot_log_overflow, clear_boot_log, critical_count, disable_boot_log,
    enable_boot_log, error_count, get_boot_log_stats, get_entries_by_level, get_last_entries,
    has_critical_errors, has_errors, is_boot_log_enabled, store_boot_log, store_boot_message,
    warn_count, BootLogStats, BOOT_LOG_CAPACITY,
};
pub use ring::{LogRingBuffer, LogRingIterator, DEFAULT_RING_CAPACITY};
