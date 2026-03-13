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

use super::output::{write_log, write_log_global};

pub use super::output::init_logger;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

#[inline]
pub fn log_info_st(st: &mut SystemTable<Boot>, category: &str, message: &str) {
    write_log(st, LogLevel::Info, category, message);
}

#[inline]
pub fn log_warn_st(st: &mut SystemTable<Boot>, category: &str, message: &str) {
    write_log(st, LogLevel::Warn, category, message);
}

#[inline]
pub fn log_error_st(st: &mut SystemTable<Boot>, category: &str, message: &str) {
    write_log(st, LogLevel::Error, category, message);
}

#[inline]
pub fn log_debug_st(st: &mut SystemTable<Boot>, category: &str, message: &str) {
    write_log(st, LogLevel::Debug, category, message);
}

#[inline]
pub fn log_critical_st(st: &mut SystemTable<Boot>, category: &str, message: &str) {
    write_log(st, LogLevel::Critical, category, message);
}

#[inline]
pub fn log_info(category: &str, message: &str) {
    write_log_global(LogLevel::Info, category, message);
}

#[inline]
pub fn log_warn(category: &str, message: &str) {
    write_log_global(LogLevel::Warn, category, message);
}

#[inline]
pub fn log_error(category: &str, message: &str) {
    write_log_global(LogLevel::Error, category, message);
}

#[inline]
pub fn log_debug(category: &str, message: &str) {
    write_log_global(LogLevel::Debug, category, message);
}

#[inline]
pub fn log_critical(category: &str, message: &str) {
    write_log_global(LogLevel::Critical, category, message);
}
