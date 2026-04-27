// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::ipc::{InboxError, InboxStatsSnapshot};
use crate::test::framework::TestResult;
use alloc::string::String;

pub(crate) fn test_inbox_error_not_found() -> TestResult {
    let err = InboxError::NotFound { module: String::from("test_module") };
    if err.as_str() != "Inbox not found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_full() -> TestResult {
    let err = InboxError::Full { module: String::from("busy_module"), capacity: 1024 };
    if err.as_str() != "Inbox full" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_timeout() -> TestResult {
    let err = InboxError::Timeout { module: String::from("slow_module"), waited_ms: 5000 };
    if err.as_str() != "Enqueue timeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_invalid_capacity() -> TestResult {
    let err = InboxError::InvalidCapacity { value: 5, min: 16, max: 65536 };
    if err.as_str() != "Invalid capacity" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_empty_module_name() -> TestResult {
    let err = InboxError::EmptyModuleName;
    if err.as_str() != "Empty module name" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_display_not_found() -> TestResult {
    let err = InboxError::NotFound { module: String::from("missing") };
    let display = alloc::format!("{}", err);
    if !display.contains("missing") {
        return TestResult::Fail;
    }
    if !display.contains("not found") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_display_full() -> TestResult {
    let err = InboxError::Full { module: String::from("full_module"), capacity: 256 };
    let display = alloc::format!("{}", err);
    if !display.contains("full_module") {
        return TestResult::Fail;
    }
    if !display.contains("256") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_display_timeout() -> TestResult {
    let err = InboxError::Timeout { module: String::from("timeout_module"), waited_ms: 10000 };
    let display = alloc::format!("{}", err);
    if !display.contains("timeout_module") {
        return TestResult::Fail;
    }
    if !display.contains("10000") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_display_invalid_capacity() -> TestResult {
    let err = InboxError::InvalidCapacity { value: 8, min: 32, max: 4096 };
    let display = alloc::format!("{}", err);
    if !display.contains("8") {
        return TestResult::Fail;
    }
    if !display.contains("32") {
        return TestResult::Fail;
    }
    if !display.contains("4096") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_display_empty_module_name() -> TestResult {
    let err = InboxError::EmptyModuleName;
    let display = alloc::format!("{}", err);
    if !display.contains("empty") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_clone() -> TestResult {
    let err = InboxError::NotFound { module: String::from("test") };
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_equality() -> TestResult {
    let err1 = InboxError::EmptyModuleName;
    let err2 = InboxError::EmptyModuleName;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_different_variants() -> TestResult {
    let err1 = InboxError::EmptyModuleName;
    let err2 = InboxError::NotFound { module: String::from("x") };
    if err1 == err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_debug() -> TestResult {
    let err = InboxError::Full { module: String::from("test"), capacity: 100 };
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("Full") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_all_variants_have_str() -> TestResult {
    let errors = [
        InboxError::NotFound { module: String::from("x") },
        InboxError::Full { module: String::from("x"), capacity: 0 },
        InboxError::Timeout { module: String::from("x"), waited_ms: 0 },
        InboxError::InvalidCapacity { value: 0, min: 0, max: 0 },
        InboxError::EmptyModuleName,
    ];
    for err in errors {
        if err.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_stats_snapshot_display() -> TestResult {
    let snap = InboxStatsSnapshot {
        enqueued: 100,
        dequeued: 90,
        dropped_full: 5,
        timeouts: 2,
        peak_size: 50,
        current_size: 10,
        capacity: 1024,
    };
    let display = alloc::format!("{}", snap);
    if !display.contains("100") {
        return TestResult::Fail;
    }
    if !display.contains("90") {
        return TestResult::Fail;
    }
    if !display.contains("10/1024") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_stats_snapshot_clone() -> TestResult {
    let snap = InboxStatsSnapshot {
        enqueued: 100,
        dequeued: 90,
        dropped_full: 5,
        timeouts: 2,
        peak_size: 50,
        current_size: 10,
        capacity: 1024,
    };
    let cloned = snap.clone();
    if snap.enqueued != cloned.enqueued {
        return TestResult::Fail;
    }
    if snap.dequeued != cloned.dequeued {
        return TestResult::Fail;
    }
    if snap.dropped_full != cloned.dropped_full {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_stats_snapshot_copy() -> TestResult {
    let snap = InboxStatsSnapshot {
        enqueued: 50,
        dequeued: 40,
        dropped_full: 3,
        timeouts: 1,
        peak_size: 25,
        current_size: 5,
        capacity: 512,
    };
    let copied = snap;
    if snap.enqueued != copied.enqueued {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_stats_snapshot_debug() -> TestResult {
    let snap = InboxStatsSnapshot {
        enqueued: 0,
        dequeued: 0,
        dropped_full: 0,
        timeouts: 0,
        peak_size: 0,
        current_size: 0,
        capacity: 64,
    };
    let debug_str = alloc::format!("{:?}", snap);
    if !debug_str.contains("InboxStatsSnapshot") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_stats_snapshot_empty() -> TestResult {
    let snap = InboxStatsSnapshot {
        enqueued: 0,
        dequeued: 0,
        dropped_full: 0,
        timeouts: 0,
        peak_size: 0,
        current_size: 0,
        capacity: 128,
    };
    if snap.enqueued != 0 {
        return TestResult::Fail;
    }
    if snap.dequeued != 0 {
        return TestResult::Fail;
    }
    if snap.current_size != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_stats_snapshot_full_utilization() -> TestResult {
    let snap = InboxStatsSnapshot {
        enqueued: 1000,
        dequeued: 500,
        dropped_full: 0,
        timeouts: 0,
        peak_size: 500,
        current_size: 500,
        capacity: 500,
    };
    if snap.current_size != snap.capacity {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_stats_snapshot_with_drops() -> TestResult {
    let snap = InboxStatsSnapshot {
        enqueued: 1000,
        dequeued: 950,
        dropped_full: 100,
        timeouts: 10,
        peak_size: 256,
        current_size: 50,
        capacity: 256,
    };
    if !(snap.dropped_full > 0) {
        return TestResult::Fail;
    }
    if !(snap.timeouts > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_stats_snapshot_large_values() -> TestResult {
    let snap = InboxStatsSnapshot {
        enqueued: u64::MAX,
        dequeued: u64::MAX - 1,
        dropped_full: 1_000_000,
        timeouts: 500_000,
        peak_size: usize::MAX,
        current_size: 1,
        capacity: 65536,
    };
    let display = alloc::format!("{}", snap);
    if display.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_with_special_characters() -> TestResult {
    let err = InboxError::NotFound { module: String::from("module/with/slashes") };
    let display = alloc::format!("{}", err);
    if !display.contains("module/with/slashes") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_with_unicode() -> TestResult {
    let err = InboxError::NotFound { module: String::from("模块") };
    let display = alloc::format!("{}", err);
    if !display.contains("模块") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_full_zero_capacity() -> TestResult {
    let err = InboxError::Full { module: String::from("mod"), capacity: 0 };
    let display = alloc::format!("{}", err);
    if !display.contains("0") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_timeout_zero_wait() -> TestResult {
    let err = InboxError::Timeout { module: String::from("mod"), waited_ms: 0 };
    let display = alloc::format!("{}", err);
    if !display.contains("0ms") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_error_invalid_capacity_edge_case() -> TestResult {
    let err = InboxError::InvalidCapacity { value: 0, min: 1, max: 1 };
    let display = alloc::format!("{}", err);
    if !display.contains("1") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_stats_pending_messages() -> TestResult {
    let snap = InboxStatsSnapshot {
        enqueued: 100,
        dequeued: 80,
        dropped_full: 0,
        timeouts: 0,
        peak_size: 30,
        current_size: 20,
        capacity: 100,
    };
    if snap.enqueued - snap.dequeued != snap.current_size as u64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inbox_stats_display_format() -> TestResult {
    let snap = InboxStatsSnapshot {
        enqueued: 42,
        dequeued: 30,
        dropped_full: 2,
        timeouts: 1,
        peak_size: 15,
        current_size: 12,
        capacity: 64,
    };
    let display = alloc::format!("{}", snap);
    if !display.contains("enq:42") {
        return TestResult::Fail;
    }
    if !display.contains("deq:30") {
        return TestResult::Fail;
    }
    if !display.contains("drop:2") {
        return TestResult::Fail;
    }
    if !display.contains("timeout:1") {
        return TestResult::Fail;
    }
    if !display.contains("12/64") {
        return TestResult::Fail;
    }
    if !display.contains("peak:15") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
