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

mod buffer;
mod constants;
mod entry;
mod log;
mod query;
mod stats;

pub use buffer::BUFFER;
pub use constants::{capacity, MAX_LOG_ENTRIES};
pub use entry::AuditEntry;
pub use log::{clear_log, is_empty, log_count, log_failure, log_raw, log_success, log_use};
pub use query::{
    get_by_action, get_by_capability, get_by_module, get_by_time_range, get_failures, get_log,
    get_recent, get_stats, get_successes, reset_stats,
};
pub use stats::{AuditCounters, AuditStatsSnapshot, STATS};
