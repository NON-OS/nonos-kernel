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

use crate::drivers::console::types::*;

#[test]
fn test_log_level_values() {
    assert_eq!(LogLevel::Trace as u8, 0);
    assert_eq!(LogLevel::Debug as u8, 1);
    assert_eq!(LogLevel::Info as u8, 2);
    assert_eq!(LogLevel::Warning as u8, 3);
    assert_eq!(LogLevel::Error as u8, 4);
    assert_eq!(LogLevel::Critical as u8, 5);
}

#[test]
fn test_log_level_default() {
    assert_eq!(LogLevel::default(), LogLevel::Info);
}

#[test]
fn test_log_level_colors() {
    assert_eq!(LogLevel::Trace.color(), Color::DarkGrey);
    assert_eq!(LogLevel::Debug.color(), Color::LightGrey);
    assert_eq!(LogLevel::Info.color(), Color::White);
    assert_eq!(LogLevel::Warning.color(), Color::Yellow);
    assert_eq!(LogLevel::Error.color(), Color::LightRed);
    assert_eq!(LogLevel::Critical.color(), Color::Red);
}

#[test]
fn test_log_level_as_str() {
    assert_eq!(LogLevel::Trace.as_str(), "TRACE");
    assert_eq!(LogLevel::Debug.as_str(), "DEBUG");
    assert_eq!(LogLevel::Info.as_str(), "INFO");
    assert_eq!(LogLevel::Warning.as_str(), "WARN");
    assert_eq!(LogLevel::Error.as_str(), "ERROR");
    assert_eq!(LogLevel::Critical.as_str(), "CRIT");
}

#[test]
fn test_log_level_ordering() {
    assert!(LogLevel::Trace < LogLevel::Debug);
    assert!(LogLevel::Debug < LogLevel::Info);
    assert!(LogLevel::Info < LogLevel::Warning);
    assert!(LogLevel::Warning < LogLevel::Error);
    assert!(LogLevel::Error < LogLevel::Critical);
}

#[test]
fn test_console_stats_new() {
    let stats = ConsoleStats::new();
    assert_eq!(stats.messages_written.load(core::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.bytes_written.load(core::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.errors.load(core::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.uptime_ticks.load(core::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn test_console_stats_default() {
    let stats = ConsoleStats::default();
    assert_eq!(stats.messages_written.load(core::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn test_console_stats_inc_messages() {
    let stats = ConsoleStats::new();
    stats.inc_messages();
    stats.inc_messages();
    assert_eq!(stats.messages_written.load(core::sync::atomic::Ordering::Relaxed), 2);
}

#[test]
fn test_console_stats_add_bytes() {
    let stats = ConsoleStats::new();
    stats.add_bytes(100);
    stats.add_bytes(50);
    assert_eq!(stats.bytes_written.load(core::sync::atomic::Ordering::Relaxed), 150);
}

#[test]
fn test_console_stats_inc_errors() {
    let stats = ConsoleStats::new();
    stats.inc_errors();
    assert_eq!(stats.errors.load(core::sync::atomic::Ordering::Relaxed), 1);
}

#[test]
fn test_console_stats_snapshot() {
    let stats = ConsoleStats::new();
    stats.inc_messages();
    stats.add_bytes(42);
    stats.inc_errors();
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.messages_written, 1);
    assert_eq!(snapshot.bytes_written, 42);
    assert_eq!(snapshot.errors, 1);
}
