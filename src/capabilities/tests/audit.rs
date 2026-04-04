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

use crate::capabilities::*;

#[test]
fn test_audit_entry_in_time_range_true() {
    let entry = AuditEntry {
        timestamp_ms: 500,
        owner_module: 1,
        action: "test",
        capability: None,
        nonce: 0,
        success: true,
    };
    assert!(entry.in_time_range(0, 1000));
    assert!(entry.in_time_range(500, 500));
}

#[test]
fn test_audit_entry_in_time_range_false() {
    let entry = AuditEntry {
        timestamp_ms: 500,
        owner_module: 1,
        action: "test",
        capability: None,
        nonce: 0,
        success: true,
    };
    assert!(!entry.in_time_range(0, 100));
    assert!(!entry.in_time_range(600, 1000));
}

#[test]
fn test_audit_entry_matches_module_true() {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 42,
        action: "test",
        capability: None,
        nonce: 0,
        success: true,
    };
    assert!(entry.matches_module(42));
}

#[test]
fn test_audit_entry_matches_module_false() {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 42,
        action: "test",
        capability: None,
        nonce: 0,
        success: true,
    };
    assert!(!entry.matches_module(99));
}

#[test]
fn test_audit_entry_matches_action_true() {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 1,
        action: "read_file",
        capability: None,
        nonce: 0,
        success: true,
    };
    assert!(entry.matches_action("read_file"));
}

#[test]
fn test_audit_entry_matches_action_false() {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 1,
        action: "read_file",
        capability: None,
        nonce: 0,
        success: true,
    };
    assert!(!entry.matches_action("write_file"));
}

#[test]
fn test_audit_entry_matches_capability_true() {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 1,
        action: "test",
        capability: Some(Capability::Admin),
        nonce: 0,
        success: true,
    };
    assert!(entry.matches_capability(Capability::Admin));
}

#[test]
fn test_audit_entry_matches_capability_false() {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 1,
        action: "test",
        capability: Some(Capability::Admin),
        nonce: 0,
        success: true,
    };
    assert!(!entry.matches_capability(Capability::Debug));
}

#[test]
fn test_audit_entry_matches_capability_none() {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 1,
        action: "test",
        capability: None,
        nonce: 0,
        success: true,
    };
    assert!(!entry.matches_capability(Capability::Admin));
}

#[test]
fn test_audit_entry_display_success() {
    let entry = AuditEntry {
        timestamp_ms: 1000,
        owner_module: 42,
        action: "test_action",
        capability: Some(Capability::Network),
        nonce: 0x1234,
        success: true,
    };
    let display = alloc::format!("{}", entry);
    assert!(display.contains("1000ms"));
    assert!(display.contains("mod:42"));
    assert!(display.contains("test_action"));
    assert!(display.contains("OK"));
}

#[test]
fn test_audit_entry_display_failure() {
    let entry = AuditEntry {
        timestamp_ms: 1000,
        owner_module: 42,
        action: "test_action",
        capability: None,
        nonce: 0x1234,
        success: false,
    };
    let display = alloc::format!("{}", entry);
    assert!(display.contains("FAIL"));
}

#[test]
fn test_audit_stats_snapshot_success_rate_all_success() {
    let snap = AuditStatsSnapshot {
        total_logged: 10,
        success_count: 10,
        failure_count: 0,
        current_entries: 10,
        capacity: 100,
        has_wrapped: false,
    };
    assert_eq!(snap.success_rate(), 100.0);
}

#[test]
fn test_audit_stats_snapshot_success_rate_half() {
    let snap = AuditStatsSnapshot {
        total_logged: 10,
        success_count: 5,
        failure_count: 5,
        current_entries: 10,
        capacity: 100,
        has_wrapped: false,
    };
    assert_eq!(snap.success_rate(), 50.0);
}

#[test]
fn test_audit_stats_snapshot_success_rate_zero_logged() {
    let snap = AuditStatsSnapshot {
        total_logged: 0,
        success_count: 0,
        failure_count: 0,
        current_entries: 0,
        capacity: 100,
        has_wrapped: false,
    };
    assert_eq!(snap.success_rate(), 100.0);
}

#[test]
fn test_audit_stats_snapshot_failure_rate() {
    let snap = AuditStatsSnapshot {
        total_logged: 10,
        success_count: 3,
        failure_count: 7,
        current_entries: 10,
        capacity: 100,
        has_wrapped: false,
    };
    assert_eq!(snap.failure_rate(), 70.0);
}

#[test]
fn test_audit_stats_snapshot_failure_rate_zero_logged() {
    let snap = AuditStatsSnapshot {
        total_logged: 0,
        success_count: 0,
        failure_count: 0,
        current_entries: 0,
        capacity: 100,
        has_wrapped: false,
    };
    assert_eq!(snap.failure_rate(), 0.0);
}

#[test]
fn test_audit_stats_snapshot_buffer_usage_percent() {
    let snap = AuditStatsSnapshot {
        total_logged: 0,
        success_count: 0,
        failure_count: 0,
        current_entries: 50,
        capacity: 100,
        has_wrapped: false,
    };
    assert_eq!(snap.buffer_usage_percent(), 50.0);
}

#[test]
fn test_audit_stats_snapshot_buffer_usage_percent_zero_capacity() {
    let snap = AuditStatsSnapshot {
        total_logged: 0,
        success_count: 0,
        failure_count: 0,
        current_entries: 0,
        capacity: 0,
        has_wrapped: false,
    };
    assert_eq!(snap.buffer_usage_percent(), 0.0);
}

#[test]
fn test_audit_stats_snapshot_display() {
    let snap = AuditStatsSnapshot {
        total_logged: 100,
        success_count: 80,
        failure_count: 20,
        current_entries: 50,
        capacity: 1000,
        has_wrapped: false,
    };
    let display = alloc::format!("{}", snap);
    assert!(display.contains("total:100"));
    assert!(display.contains("ok:80"));
    assert!(display.contains("fail:20"));
}

#[test]
fn test_audit_stats_snapshot_default() {
    let snap = AuditStatsSnapshot::default();
    assert_eq!(snap.total_logged, 0);
    assert_eq!(snap.success_count, 0);
    assert_eq!(snap.failure_count, 0);
}

#[test]
fn test_audit_capacity() {
    assert!(audit_capacity() > 0);
    assert_eq!(audit_capacity(), MAX_LOG_ENTRIES);
}

#[test]
fn test_max_log_entries_constant() {
    assert!(MAX_LOG_ENTRIES > 0);
}

#[test]
fn test_clear_log() {
    clear_log();
    assert!(is_empty());
    assert_eq!(log_count(), 0);
}

#[test]
fn test_log_raw() {
    clear_log();
    reset_stats();
    log_raw(100, "test_action", Some(Capability::Admin), 12345, true);
    assert_eq!(log_count(), 1);
    assert!(!is_empty());
}

#[test]
fn test_log_use_with_token() {
    clear_log();
    reset_stats();
    let tok = CapabilityToken {
        owner_module: 42,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 99999,
        signature: [0u8; 64],
    };
    log_use(&tok, "token_test", Some(Capability::Admin), true);
    assert_eq!(log_count(), 1);
}

#[test]
fn test_log_success() {
    clear_log();
    reset_stats();
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Debug],
        expires_at_ms: None,
        nonce: 1,
        signature: [0u8; 64],
    };
    log_success(&tok, "success_action", Some(Capability::Debug));
    let entries = get_successes();
    assert!(!entries.is_empty());
}

#[test]
fn test_log_failure() {
    clear_log();
    reset_stats();
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Debug],
        expires_at_ms: None,
        nonce: 1,
        signature: [0u8; 64],
    };
    log_failure(&tok, "failure_action", Some(Capability::Debug));
    let entries = get_failures();
    assert!(!entries.is_empty());
}

#[test]
fn test_get_log_returns_entries() {
    clear_log();
    log_raw(1, "action1", None, 1, true);
    log_raw(2, "action2", None, 2, false);
    let log = get_log();
    assert_eq!(log.len(), 2);
}

#[test]
fn test_get_recent() {
    clear_log();
    for i in 0..10 {
        log_raw(i, "action", None, i, true);
    }
    let recent = get_recent(3);
    assert_eq!(recent.len(), 3);
}

#[test]
fn test_get_recent_more_than_available() {
    clear_log();
    log_raw(1, "action", None, 1, true);
    let recent = get_recent(100);
    assert_eq!(recent.len(), 1);
}

#[test]
fn test_get_stats() {
    clear_log();
    reset_stats();
    log_raw(1, "action", None, 1, true);
    log_raw(2, "action", None, 2, false);
    let stats = get_stats();
    assert_eq!(stats.total_logged, 2);
    assert_eq!(stats.success_count, 1);
    assert_eq!(stats.failure_count, 1);
    assert_eq!(stats.current_entries, 2);
}

#[test]
fn test_reset_stats() {
    log_raw(1, "action", None, 1, true);
    reset_stats();
    let stats = get_stats();
    assert_eq!(stats.total_logged, 0);
    assert_eq!(stats.success_count, 0);
    assert_eq!(stats.failure_count, 0);
}

#[test]
fn test_get_by_module() {
    clear_log();
    log_raw(100, "action", None, 1, true);
    log_raw(200, "action", None, 2, true);
    log_raw(100, "action2", None, 3, false);
    let entries = get_by_module(100);
    assert_eq!(entries.len(), 2);
}

#[test]
fn test_get_by_action() {
    clear_log();
    log_raw(1, "read", None, 1, true);
    log_raw(2, "write", None, 2, true);
    log_raw(3, "read", None, 3, true);
    let entries = get_by_action("read");
    assert_eq!(entries.len(), 2);
}

#[test]
fn test_get_by_capability() {
    clear_log();
    log_raw(1, "action", Some(Capability::Admin), 1, true);
    log_raw(2, "action", Some(Capability::Debug), 2, true);
    log_raw(3, "action", Some(Capability::Admin), 3, true);
    let entries = get_by_capability(Capability::Admin);
    assert_eq!(entries.len(), 2);
}

#[test]
fn test_get_successes() {
    clear_log();
    log_raw(1, "action", None, 1, true);
    log_raw(2, "action", None, 2, false);
    log_raw(3, "action", None, 3, true);
    let entries = get_successes();
    assert_eq!(entries.len(), 2);
}

#[test]
fn test_get_failures() {
    clear_log();
    log_raw(1, "action", None, 1, true);
    log_raw(2, "action", None, 2, false);
    log_raw(3, "action", None, 3, false);
    let entries = get_failures();
    assert_eq!(entries.len(), 2);
}
