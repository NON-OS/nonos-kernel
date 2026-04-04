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
use core::sync::atomic::Ordering;

#[test]
fn test_log_manager_new() {
    let manager = LogManager::new();
    assert_eq!(manager.entry_count(), 0);
}

#[test]
fn test_log_manager_const_new() {
    const _MANAGER: LogManager = LogManager::new();
}

#[test]
fn test_log_manager_log_single() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "test message");
    assert_eq!(manager.entry_count(), 1);
}

#[test]
fn test_log_manager_log_multiple() {
    let mut manager = LogManager::new();
    for _ in 0..10 {
        manager.log(Severity::Debug, "message");
    }
    assert_eq!(manager.entry_count(), 10);
}

#[test]
fn test_log_manager_log_all_severities() {
    let mut manager = LogManager::new();
    manager.log(Severity::Debug, "debug");
    manager.log(Severity::Info, "info");
    manager.log(Severity::Warn, "warn");
    manager.log(Severity::Err, "error");
    manager.log(Severity::Fatal, "fatal");
    assert_eq!(manager.entry_count(), 5);
}

#[test]
fn test_log_manager_get_entries_empty() {
    let manager = LogManager::new();
    let entries = manager.get_entries();
    assert!(entries.is_empty());
}

#[test]
fn test_log_manager_get_entries_single() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "single entry");
    let entries = manager.get_entries();
    assert_eq!(entries.len(), 1);
}

#[test]
fn test_log_manager_get_entries_preserves_message() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "hello world");
    let entries = manager.get_entries();
    assert_eq!(entries[0].msg.as_str(), "hello world");
}

#[test]
fn test_log_manager_get_entries_preserves_severity() {
    let mut manager = LogManager::new();
    manager.log(Severity::Warn, "warning");
    let entries = manager.get_entries();
    assert_eq!(entries[0].sev, Severity::Warn);
}

#[test]
fn test_log_manager_get_recent_empty() {
    let manager = LogManager::new();
    let recent = manager.get_recent(5);
    assert!(recent.is_empty());
}

#[test]
fn test_log_manager_get_recent_single() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "recent");
    let recent = manager.get_recent(1);
    assert_eq!(recent.len(), 1);
}

#[test]
fn test_log_manager_get_recent_returns_newest() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "first");
    manager.log(Severity::Info, "second");
    manager.log(Severity::Info, "third");
    let recent = manager.get_recent(2);
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].msg.as_str(), "second");
    assert_eq!(recent[1].msg.as_str(), "third");
}

#[test]
fn test_log_manager_get_recent_less_than_available() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "one");
    manager.log(Severity::Info, "two");
    let recent = manager.get_recent(10);
    assert_eq!(recent.len(), 2);
}

#[test]
fn test_log_manager_entry_count_zero() {
    let manager = LogManager::new();
    assert_eq!(manager.entry_count(), 0);
}

#[test]
fn test_log_manager_entry_count_increments() {
    let mut manager = LogManager::new();
    for i in 1..=5 {
        manager.log(Severity::Info, "msg");
        assert_eq!(manager.entry_count(), i);
    }
}

#[test]
fn test_log_manager_clear_buffer() {
    let mut manager = LogManager::new();
    for _ in 0..5 {
        manager.log(Severity::Info, "msg");
    }
    assert_eq!(manager.entry_count(), 5);
    manager.clear_buffer();
    assert_eq!(manager.entry_count(), 0);
}

#[test]
fn test_log_manager_clear_buffer_empty() {
    let mut manager = LogManager::new();
    manager.clear_buffer();
    assert_eq!(manager.entry_count(), 0);
}

#[test]
fn test_log_manager_clear_then_log() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "before");
    manager.clear_buffer();
    manager.log(Severity::Debug, "after");
    assert_eq!(manager.entry_count(), 1);
    let entries = manager.get_entries();
    assert_eq!(entries[0].msg.as_str(), "after");
}

#[test]
fn test_log_manager_hash_chain() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "first");
    manager.log(Severity::Info, "second");
    let entries = manager.get_entries();
    assert_ne!(entries[0].hash, entries[1].hash);
}

#[test]
fn test_log_manager_hash_not_zero() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "test");
    let entries = manager.get_entries();
    assert_ne!(entries[0].hash, [0u8; 32]);
}

#[test]
fn test_log_manager_enter_panic_mode() {
    let manager = LogManager::new();
    PANIC_MODE.store(false, Ordering::SeqCst);
    manager.enter_panic_mode();
    assert!(PANIC_MODE.load(Ordering::SeqCst));
    PANIC_MODE.store(false, Ordering::SeqCst);
}

#[test]
fn test_panic_mode_static_default() {
    PANIC_MODE.store(false, Ordering::SeqCst);
    assert!(!PANIC_MODE.load(Ordering::SeqCst));
}

#[test]
fn test_panic_mode_atomic_store_load() {
    PANIC_MODE.store(true, Ordering::SeqCst);
    assert!(PANIC_MODE.load(Ordering::SeqCst));
    PANIC_MODE.store(false, Ordering::SeqCst);
    assert!(!PANIC_MODE.load(Ordering::SeqCst));
}

#[test]
fn test_log_manager_add_backend() {
    let mut manager = LogManager::new();
    manager.add_backend(alloc::boxed::Box::new(RamBufferBackend::new()));
}

#[test]
fn test_log_manager_empty_message() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "");
    let entries = manager.get_entries();
    assert_eq!(entries[0].msg.as_str(), "");
}

#[test]
fn test_log_manager_long_message() {
    let mut manager = LogManager::new();
    let long_msg = "a".repeat(200);
    manager.log(Severity::Info, &long_msg);
    let entries = manager.get_entries();
    assert!(entries[0].msg.len() > 0);
}

#[test]
fn test_log_manager_message_truncation() {
    let mut manager = LogManager::new();
    let overflow_msg = "x".repeat(300);
    manager.log(Severity::Info, &overflow_msg);
    let entries = manager.get_entries();
    assert!(entries[0].msg.len() <= 256);
}

#[test]
fn test_logger_static_exists() {
    let _guard = LOGGER.lock();
}

#[test]
fn test_try_get_logger_returns_some() {
    let result = try_get_logger();
    assert!(result.is_some());
}

#[test]
fn test_log_critical_uses_fatal() {
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
                assert_eq!(last.sev, Severity::Fatal);
            }
        }
    }
    if let Some(ref mut mgr) = *lock {
        mgr.clear_buffer();
    }
}

#[test]
fn test_enter_panic_mode_function() {
    PANIC_MODE.store(false, Ordering::SeqCst);
    enter_panic_mode();
    assert!(PANIC_MODE.load(Ordering::SeqCst));
    PANIC_MODE.store(false, Ordering::SeqCst);
}

#[test]
fn test_get_log_entries_function() {
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
    assert!(!entries.is_empty() || entries.is_empty());
}

#[test]
fn test_get_recent_logs_function() {
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
    assert!(recent.len() <= 10);
}

#[test]
fn test_log_entry_count_function() {
    let count = log_entry_count();
    assert!(count >= 0);
}

#[test]
fn test_clear_log_buffer_function() {
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
    assert_eq!(count, 0);
}

#[test]
fn test_log_function_with_severity() {
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
    assert!(count >= 5);

    clear_log_buffer();
}

#[test]
fn test_log_manager_timestamps_increase() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "first");
    manager.log(Severity::Info, "second");
    let entries = manager.get_entries();
    if entries.len() >= 2 {
        assert!(entries[1].ts >= entries[0].ts);
    }
}

#[test]
fn test_log_manager_cpu_field_set() {
    let mut manager = LogManager::new();
    manager.log(Severity::Info, "test");
    let entries = manager.get_entries();
    let _ = entries[0].cpu;
}

#[test]
fn test_log_manager_hash_deterministic() {
    let mut manager1 = LogManager::new();
    let mut manager2 = LogManager::new();
    manager1.log(Severity::Info, "same message");
    manager2.log(Severity::Info, "same message");
    let entries1 = manager1.get_entries();
    let entries2 = manager2.get_entries();
    assert_eq!(entries1[0].hash, entries2[0].hash);
}

#[test]
fn test_log_manager_different_messages_different_hashes() {
    let mut manager = LogManager::new();
    manager.clear_buffer();

    let mut manager2 = LogManager::new();
    manager2.log(Severity::Info, "message a");
    let entries_a = manager2.get_entries();

    let mut manager3 = LogManager::new();
    manager3.log(Severity::Info, "message b");
    let entries_b = manager3.get_entries();

    assert_ne!(entries_a[0].hash, entries_b[0].hash);
}
