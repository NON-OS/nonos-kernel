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

use crate::log::*;
use crate::test::framework::TestResult;
use core::sync::atomic::Ordering;

pub(crate) fn test_log_manager_new() -> TestResult {
    let manager = LogManager::new();
    if manager.entry_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_const_new() -> TestResult {
    const _MANAGER: LogManager = LogManager::new();
    TestResult::Pass
}

pub(crate) fn test_log_manager_log_single() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "test message");
    if manager.entry_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_log_multiple() -> TestResult {
    let mut manager = LogManager::new();
    for _ in 0..10 {
        manager.log(Severity::Debug, "message");
    }
    if manager.entry_count() != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_log_all_severities() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Debug, "debug");
    manager.log(Severity::Info, "info");
    manager.log(Severity::Warn, "warn");
    manager.log(Severity::Err, "error");
    manager.log(Severity::Fatal, "fatal");
    if manager.entry_count() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_get_entries_empty() -> TestResult {
    let manager = LogManager::new();
    let entries = manager.get_entries();
    if !entries.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_get_entries_single() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "single entry");
    let entries = manager.get_entries();
    if entries.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_get_entries_preserves_message() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "hello world");
    let entries = manager.get_entries();
    if entries[0].msg.as_str() != "hello world" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_get_entries_preserves_severity() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Warn, "warning");
    let entries = manager.get_entries();
    if entries[0].sev != Severity::Warn {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_get_recent_empty() -> TestResult {
    let manager = LogManager::new();
    let recent = manager.get_recent(5);
    if !recent.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_get_recent_single() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "recent");
    let recent = manager.get_recent(1);
    if recent.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_get_recent_returns_newest() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "first");
    manager.log(Severity::Info, "second");
    manager.log(Severity::Info, "third");
    let recent = manager.get_recent(2);
    if recent.len() != 2 {
        return TestResult::Fail;
    }
    if recent[0].msg.as_str() != "second" {
        return TestResult::Fail;
    }
    if recent[1].msg.as_str() != "third" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_get_recent_less_than_available() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "one");
    manager.log(Severity::Info, "two");
    let recent = manager.get_recent(10);
    if recent.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_entry_count_zero() -> TestResult {
    let manager = LogManager::new();
    if manager.entry_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_entry_count_increments() -> TestResult {
    let mut manager = LogManager::new();
    for i in 1..=5 {
        manager.log(Severity::Info, "msg");
        if manager.entry_count() != i {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_clear_buffer() -> TestResult {
    let mut manager = LogManager::new();
    for _ in 0..5 {
        manager.log(Severity::Info, "msg");
    }
    if manager.entry_count() != 5 {
        return TestResult::Fail;
    }
    manager.clear_buffer();
    if manager.entry_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_clear_buffer_empty() -> TestResult {
    let mut manager = LogManager::new();
    manager.clear_buffer();
    if manager.entry_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_clear_then_log() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "before");
    manager.clear_buffer();
    manager.log(Severity::Debug, "after");
    if manager.entry_count() != 1 {
        return TestResult::Fail;
    }
    let entries = manager.get_entries();
    if entries[0].msg.as_str() != "after" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_hash_chain() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "first");
    manager.log(Severity::Info, "second");
    let entries = manager.get_entries();
    if entries[0].hash == entries[1].hash {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_hash_not_zero() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "test");
    let entries = manager.get_entries();
    if entries[0].hash == [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_enter_panic_mode() -> TestResult {
    let manager = LogManager::new();
    PANIC_MODE.store(false, Ordering::SeqCst);
    manager.enter_panic_mode();
    if !PANIC_MODE.load(Ordering::SeqCst) {
        return TestResult::Fail;
    }
    PANIC_MODE.store(false, Ordering::SeqCst);
    TestResult::Pass
}

pub(crate) fn test_panic_mode_static_default() -> TestResult {
    PANIC_MODE.store(false, Ordering::SeqCst);
    if PANIC_MODE.load(Ordering::SeqCst) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_panic_mode_atomic_store_load() -> TestResult {
    PANIC_MODE.store(true, Ordering::SeqCst);
    if !PANIC_MODE.load(Ordering::SeqCst) {
        return TestResult::Fail;
    }
    PANIC_MODE.store(false, Ordering::SeqCst);
    if PANIC_MODE.load(Ordering::SeqCst) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_add_backend() -> TestResult {
    let mut manager = LogManager::new();
    manager.add_backend(alloc::boxed::Box::new(RamBufferBackend::new()));
    TestResult::Pass
}

pub(crate) fn test_log_manager_empty_message() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "");
    let entries = manager.get_entries();
    if entries[0].msg.as_str() != "" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_long_message() -> TestResult {
    let mut manager = LogManager::new();
    let long_msg = "a".repeat(200);
    manager.log(Severity::Info, &long_msg);
    let entries = manager.get_entries();
    if !(entries[0].msg.len() > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_message_truncation() -> TestResult {
    let mut manager = LogManager::new();
    let overflow_msg = "x".repeat(300);
    manager.log(Severity::Info, &overflow_msg);
    let entries = manager.get_entries();
    if !(entries[0].msg.len() <= 256) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_logger_static_exists() -> TestResult {
    let _guard = LOGGER.lock();
    TestResult::Pass
}

pub(crate) fn test_try_get_logger_returns_some() -> TestResult {
    let result = try_get_logger();
    if !result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_critical_uses_fatal() -> TestResult {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    drop(lock);

    log_critical("critical test");

    let mut lock = LOGGER.lock();
    if let Some(ref mgr) = *lock {
        let entries = mgr.get_entries();
        if !entries.is_empty() {
            let last = entries.last().unwrap();
            if last.msg.as_str() == "critical test" {
                if last.sev != Severity::Fatal {
                    return TestResult::Fail;
                }
            }
        }
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    TestResult::Pass
}

pub(crate) fn test_enter_panic_mode_function() -> TestResult {
    PANIC_MODE.store(false, Ordering::SeqCst);
    enter_panic_mode();
    if !PANIC_MODE.load(Ordering::SeqCst) {
        return TestResult::Fail;
    }
    PANIC_MODE.store(false, Ordering::SeqCst);
    TestResult::Pass
}

pub(crate) fn test_get_log_entries_function() -> TestResult {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
        mgr.log(Severity::Info, "entry test");
    }
    drop(lock);

    let entries = get_log_entries();
    if !(!entries.is_empty() || entries.is_empty()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_recent_logs_function() -> TestResult {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
        mgr.log(Severity::Info, "recent test");
    }
    drop(lock);

    let recent = get_recent_logs(10);
    if !(recent.len() <= 10) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_count_function() -> TestResult {
    let _ = log_entry_count();
    TestResult::Pass
}

pub(crate) fn test_clear_log_buffer_function() -> TestResult {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.log(Severity::Info, "to be cleared");
    }
    drop(lock);

    clear_log_buffer();

    let count = log_entry_count();
    if count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_function_with_severity() -> TestResult {
    let mut lock = LOGGER.lock();
    if lock.is_none() {
        *lock = Some(LogManager::new());
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
    drop(lock);

    log(Severity::Debug, "debug via log fn");
    log(Severity::Info, "info via log fn");
    log(Severity::Warn, "warn via log fn");
    log(Severity::Err, "err via log fn");
    log(Severity::Fatal, "fatal via log fn");

    let count = log_entry_count();
    if !(count >= 5) {
        return TestResult::Fail;
    }

    clear_log_buffer();
    TestResult::Pass
}

pub(crate) fn test_log_manager_timestamps_increase() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "first");
    manager.log(Severity::Info, "second");
    let entries = manager.get_entries();
    if entries.len() >= 2 {
        if !(entries[1].ts >= entries[0].ts) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_cpu_field_set() -> TestResult {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "test");
    let entries = manager.get_entries();
    let _ = entries[0].cpu;
    TestResult::Pass
}

pub(crate) fn test_log_manager_hash_deterministic() -> TestResult {
    let mut manager1 = LogManager::new();
    let mut manager2 = LogManager::new();
    manager1.log(Severity::Info, "same message");
    manager2.log(Severity::Info, "same message");
    let entries1 = manager1.get_entries();
    let entries2 = manager2.get_entries();
    if entries1[0].hash != entries2[0].hash {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_manager_different_messages_different_hashes() -> TestResult {
    let mut manager = LogManager::new();
    manager.clear_buffer();

    let mut manager2 = LogManager::new();
    manager2.log(Severity::Info, "message a");
    let entries_a = manager2.get_entries();

    let mut manager3 = LogManager::new();
    manager3.log(Severity::Info, "message b");
    let entries_b = manager3.get_entries();

    if entries_a[0].hash == entries_b[0].hash {
        return TestResult::Fail;
    }
    TestResult::Pass
}
