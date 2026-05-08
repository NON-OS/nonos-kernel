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

pub use super::global::init_global_state as init_logger;
pub use super::output::{
    log_critical, log_critical_st, log_debug, log_debug_st, log_error, log_error_st, log_fatal,
    log_fatal_st, log_info, log_info_st, log_trace, log_trace_st, log_warn, log_warn_st,
};
pub use super::types::LogLevel;
