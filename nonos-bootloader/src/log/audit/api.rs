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

use uefi::prelude::*;

use super::console::{write_log_global, write_log_st};
use crate::log::global::should_log;
use crate::log::types::LogLevel;

#[inline]
pub fn log_trace_st(st: &mut SystemTable<Boot>, category: &str, message: &str) {
    write_log_st(st, LogLevel::Trace, category, message);
}

#[inline]
pub fn log_debug_st(st: &mut SystemTable<Boot>, category: &str, message: &str) {
    write_log_st(st, LogLevel::Debug, category, message);
}

#[inline]
pub fn log_info_st(st: &mut SystemTable<Boot>, category: &str, message: &str) {
    write_log_st(st, LogLevel::Info, category, message);
}

#[inline]
pub fn log_warn_st(st: &mut SystemTable<Boot>, category: &str, message: &str) {
    write_log_st(st, LogLevel::Warn, category, message);
}

#[inline]
pub fn log_error_st(st: &mut SystemTable<Boot>, category: &str, message: &str) {
    write_log_st(st, LogLevel::Error, category, message);
}

#[inline]
pub fn log_critical_st(st: &mut SystemTable<Boot>, category: &str, message: &str) {
    write_log_st(st, LogLevel::Critical, category, message);
}

#[inline]
pub fn log_fatal_st(st: &mut SystemTable<Boot>, category: &str, message: &str) {
    write_log_st(st, LogLevel::Fatal, category, message);
}

#[inline]
pub fn log_trace(category: &str, message: &str) {
    if should_log(LogLevel::Trace) {
        write_log_global(LogLevel::Trace, category, message);
    }
}

#[inline]
pub fn log_debug(category: &str, message: &str) {
    if should_log(LogLevel::Debug) {
        write_log_global(LogLevel::Debug, category, message);
    }
}

#[inline]
pub fn log_info(category: &str, message: &str) {
    if should_log(LogLevel::Info) {
        write_log_global(LogLevel::Info, category, message);
    }
}

#[inline]
pub fn log_warn(category: &str, message: &str) {
    if should_log(LogLevel::Warn) {
        write_log_global(LogLevel::Warn, category, message);
    }
}

#[inline]
pub fn log_error(category: &str, message: &str) {
    if should_log(LogLevel::Error) {
        write_log_global(LogLevel::Error, category, message);
    }
}

#[inline]
pub fn log_critical(category: &str, message: &str) {
    if should_log(LogLevel::Critical) {
        write_log_global(LogLevel::Critical, category, message);
    }
}

#[inline]
pub fn log_fatal(category: &str, message: &str) {
    write_log_global(LogLevel::Fatal, category, message);
}

#[inline]
pub fn log_at_level(level: LogLevel, category: &str, message: &str) {
    if should_log(level) {
        write_log_global(level, category, message);
    }
}

#[inline]
pub fn log_at_level_st(st: &mut SystemTable<Boot>, level: LogLevel, category: &str, message: &str) {
    write_log_st(st, level, category, message);
}
