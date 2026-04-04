// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::ipc::nonos_inbox::error::InboxError;
use crate::ipc::nonos_inbox::stats::InboxStatsSnapshot;
use alloc::string::String;

#[test]
fn test_inbox_error_not_found() {
    let err = InboxError::NotFound {
        module: String::from("test_module"),
    };
    assert_eq!(err.as_str(), "Inbox not found");
}

#[test]
fn test_inbox_error_full() {
    let err = InboxError::Full {
        module: String::from("busy_module"),
        capacity: 1024,
    };
    assert_eq!(err.as_str(), "Inbox full");
}

#[test]
fn test_inbox_error_timeout() {
    let err = InboxError::Timeout {
        module: String::from("slow_module"),
        waited_ms: 5000,
    };
    assert_eq!(err.as_str(), "Enqueue timeout");
}

#[test]
fn test_inbox_error_invalid_capacity() {
    let err = InboxError::InvalidCapacity {
        value: 5,
        min: 16,
        max: 65536,
    };
    assert_eq!(err.as_str(), "Invalid capacity");
}

#[test]
fn test_inbox_error_empty_module_name() {
    let err = InboxError::EmptyModuleName;
    assert_eq!(err.as_str(), "Empty module name");
}

#[test]
fn test_inbox_error_display_not_found() {
    let err = InboxError::NotFound {
        module: String::from("missing"),
    };
    let display = alloc::format!("{}", err);
    assert!(display.contains("missing"));
    assert!(display.contains("not found"));
}

#[test]
fn test_inbox_error_display_full() {
    let err = InboxError::Full {
        module: String::from("full_module"),
        capacity: 256,
    };
    let display = alloc::format!("{}", err);
    assert!(display.contains("full_module"));
    assert!(display.contains("256"));
}

#[test]
fn test_inbox_error_display_timeout() {
    let err = InboxError::Timeout {
        module: String::from("timeout_module"),
        waited_ms: 10000,
    };
    let display = alloc::format!("{}", err);
    assert!(display.contains("timeout_module"));
    assert!(display.contains("10000"));
}

#[test]
fn test_inbox_error_display_invalid_capacity() {
    let err = InboxError::InvalidCapacity {
        value: 8,
        min: 32,
        max: 4096,
    };
    let display = alloc::format!("{}", err);
    assert!(display.contains("8"));
    assert!(display.contains("32"));
    assert!(display.contains("4096"));
}

#[test]
fn test_inbox_error_display_empty_module_name() {
    let err = InboxError::EmptyModuleName;
    let display = alloc::format!("{}", err);
    assert!(display.contains("empty"));
}

#[test]
fn test_inbox_error_clone() {
    let err = InboxError::NotFound {
        module: String::from("test"),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_inbox_error_equality() {
    let err1 = InboxError::EmptyModuleName;
    let err2 = InboxError::EmptyModuleName;
    assert_eq!(err1, err2);
}

#[test]
fn test_inbox_error_different_variants() {
    let err1 = InboxError::EmptyModuleName;
    let err2 = InboxError::NotFound {
        module: String::from("x"),
    };
    assert_ne!(err1, err2);
}

#[test]
fn test_inbox_error_debug() {
    let err = InboxError::Full {
        module: String::from("test"),
        capacity: 100,
    };
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("Full"));
}

#[test]
fn test_inbox_error_all_variants_have_str() {
    let errors = [
        InboxError::NotFound {
            module: String::from("x"),
        },
        InboxError::Full {
            module: String::from("x"),
            capacity: 0,
        },
        InboxError::Timeout {
            module: String::from("x"),
            waited_ms: 0,
        },
        InboxError::InvalidCapacity {
            value: 0,
            min: 0,
            max: 0,
        },
        InboxError::EmptyModuleName,
    ];
    for err in errors {
        assert!(!err.as_str().is_empty());
    }
}

#[test]
fn test_inbox_stats_snapshot_display() {
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
    assert!(display.contains("100"));
    assert!(display.contains("90"));
    assert!(display.contains("10/1024"));
}

#[test]
fn test_inbox_stats_snapshot_clone() {
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
    assert_eq!(snap.enqueued, cloned.enqueued);
    assert_eq!(snap.dequeued, cloned.dequeued);
    assert_eq!(snap.dropped_full, cloned.dropped_full);
}

#[test]
fn test_inbox_stats_snapshot_copy() {
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
    assert_eq!(snap.enqueued, copied.enqueued);
}

#[test]
fn test_inbox_stats_snapshot_debug() {
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
    assert!(debug_str.contains("InboxStatsSnapshot"));
}

#[test]
fn test_inbox_stats_snapshot_empty() {
    let snap = InboxStatsSnapshot {
        enqueued: 0,
        dequeued: 0,
        dropped_full: 0,
        timeouts: 0,
        peak_size: 0,
        current_size: 0,
        capacity: 128,
    };
    assert_eq!(snap.enqueued, 0);
    assert_eq!(snap.dequeued, 0);
    assert_eq!(snap.current_size, 0);
}

#[test]
fn test_inbox_stats_snapshot_full_utilization() {
    let snap = InboxStatsSnapshot {
        enqueued: 1000,
        dequeued: 500,
        dropped_full: 0,
        timeouts: 0,
        peak_size: 500,
        current_size: 500,
        capacity: 500,
    };
    assert_eq!(snap.current_size, snap.capacity);
}

#[test]
fn test_inbox_stats_snapshot_with_drops() {
    let snap = InboxStatsSnapshot {
        enqueued: 1000,
        dequeued: 950,
        dropped_full: 100,
        timeouts: 10,
        peak_size: 256,
        current_size: 50,
        capacity: 256,
    };
    assert!(snap.dropped_full > 0);
    assert!(snap.timeouts > 0);
}

#[test]
fn test_inbox_stats_snapshot_large_values() {
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
    assert!(!display.is_empty());
}

#[test]
fn test_inbox_error_with_special_characters() {
    let err = InboxError::NotFound {
        module: String::from("module/with/slashes"),
    };
    let display = alloc::format!("{}", err);
    assert!(display.contains("module/with/slashes"));
}

#[test]
fn test_inbox_error_with_unicode() {
    let err = InboxError::NotFound {
        module: String::from("模块"),
    };
    let display = alloc::format!("{}", err);
    assert!(display.contains("模块"));
}

#[test]
fn test_inbox_error_full_zero_capacity() {
    let err = InboxError::Full {
        module: String::from("mod"),
        capacity: 0,
    };
    let display = alloc::format!("{}", err);
    assert!(display.contains("0"));
}

#[test]
fn test_inbox_error_timeout_zero_wait() {
    let err = InboxError::Timeout {
        module: String::from("mod"),
        waited_ms: 0,
    };
    let display = alloc::format!("{}", err);
    assert!(display.contains("0ms"));
}

#[test]
fn test_inbox_error_invalid_capacity_edge_case() {
    let err = InboxError::InvalidCapacity {
        value: 0,
        min: 1,
        max: 1,
    };
    let display = alloc::format!("{}", err);
    assert!(display.contains("1"));
}

#[test]
fn test_inbox_stats_pending_messages() {
    let snap = InboxStatsSnapshot {
        enqueued: 100,
        dequeued: 80,
        dropped_full: 0,
        timeouts: 0,
        peak_size: 30,
        current_size: 20,
        capacity: 100,
    };
    assert_eq!(snap.enqueued - snap.dequeued, snap.current_size as u64);
}

#[test]
fn test_inbox_stats_display_format() {
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
    assert!(display.contains("enq:42"));
    assert!(display.contains("deq:30"));
    assert!(display.contains("drop:2"));
    assert!(display.contains("timeout:1"));
    assert!(display.contains("12/64"));
    assert!(display.contains("peak:15"));
}

