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

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Info, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Info, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Warn, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_err {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Err, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_dbg {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Debug, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_fatal {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Fatal, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Err, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Debug, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Debug, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_warning {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Warn, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Warn, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Err, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! security_log {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Fatal, &alloc::format!($($arg)*)) };
}
