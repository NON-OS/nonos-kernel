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

extern crate alloc;

use crate::capabilities::*;
use crate::test::framework::TestResult;

pub(crate) fn test_audit_entry_in_time_range_true() -> TestResult {
    let entry = AuditEntry {
        timestamp_ms: 500,
        owner_module: 1,
        action: "test",
        capability: None,
        nonce: 0,
        success: true,
    };
    if !entry.in_time_range(0, 1000) {
        return TestResult::Fail;
    }
    if !entry.in_time_range(500, 500) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_entry_in_time_range_false() -> TestResult {
    let entry = AuditEntry {
        timestamp_ms: 500,
        owner_module: 1,
        action: "test",
        capability: None,
        nonce: 0,
        success: true,
    };
    if entry.in_time_range(0, 100) {
        return TestResult::Fail;
    }
    if entry.in_time_range(600, 1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_entry_matches_module_true() -> TestResult {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 42,
        action: "test",
        capability: None,
        nonce: 0,
        success: true,
    };
    if !entry.matches_module(42) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_entry_matches_module_false() -> TestResult {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 42,
        action: "test",
        capability: None,
        nonce: 0,
        success: true,
    };
    if entry.matches_module(99) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_entry_matches_action_true() -> TestResult {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 1,
        action: "read_file",
        capability: None,
        nonce: 0,
        success: true,
    };
    if !entry.matches_action("read_file") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_entry_matches_action_false() -> TestResult {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 1,
        action: "read_file",
        capability: None,
        nonce: 0,
        success: true,
    };
    if entry.matches_action("write_file") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_entry_matches_capability_true() -> TestResult {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 1,
        action: "test",
        capability: Some(Capability::Admin),
        nonce: 0,
        success: true,
    };
    if !entry.matches_capability(Capability::Admin) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_entry_matches_capability_false() -> TestResult {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 1,
        action: "test",
        capability: Some(Capability::Admin),
        nonce: 0,
        success: true,
    };
    if entry.matches_capability(Capability::Debug) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_entry_matches_capability_none() -> TestResult {
    let entry = AuditEntry {
        timestamp_ms: 0,
        owner_module: 1,
        action: "test",
        capability: None,
        nonce: 0,
        success: true,
    };
    if entry.matches_capability(Capability::Admin) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_entry_display_success() -> TestResult {
    let entry = AuditEntry {
        timestamp_ms: 1000,
        owner_module: 42,
        action: "test_action",
        capability: Some(Capability::Network),
        nonce: 0x1234,
        success: true,
    };
    let display = alloc::format!("{}", entry);
    if !display.contains("1000ms") {
        return TestResult::Fail;
    }
    if !display.contains("mod:42") {
        return TestResult::Fail;
    }
    if !display.contains("test_action") {
        return TestResult::Fail;
    }
    if !display.contains("OK") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_entry_display_failure() -> TestResult {
    let entry = AuditEntry {
        timestamp_ms: 1000,
        owner_module: 42,
        action: "test_action",
        capability: None,
        nonce: 0x1234,
        success: false,
    };
    let display = alloc::format!("{}", entry);
    if !display.contains("FAIL") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_stats_snapshot_success_rate_all_success() -> TestResult {
    let snap = AuditStatsSnapshot {
        total_logged: 10,
        success_count: 10,
        failure_count: 0,
        current_entries: 10,
        capacity: 100,
        has_wrapped: false,
    };
    if snap.success_rate() != 100.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_stats_snapshot_success_rate_half() -> TestResult {
    let snap = AuditStatsSnapshot {
        total_logged: 10,
        success_count: 5,
        failure_count: 5,
        current_entries: 10,
        capacity: 100,
        has_wrapped: false,
    };
    if snap.success_rate() != 50.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_stats_snapshot_success_rate_zero_logged() -> TestResult {
    let snap = AuditStatsSnapshot {
        total_logged: 0,
        success_count: 0,
        failure_count: 0,
        current_entries: 0,
        capacity: 100,
        has_wrapped: false,
    };
    if snap.success_rate() != 100.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_stats_snapshot_failure_rate() -> TestResult {
    let snap = AuditStatsSnapshot {
        total_logged: 10,
        success_count: 3,
        failure_count: 7,
        current_entries: 10,
        capacity: 100,
        has_wrapped: false,
    };
    if snap.failure_rate() != 70.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_stats_snapshot_failure_rate_zero_logged() -> TestResult {
    let snap = AuditStatsSnapshot {
        total_logged: 0,
        success_count: 0,
        failure_count: 0,
        current_entries: 0,
        capacity: 100,
        has_wrapped: false,
    };
    if snap.failure_rate() != 0.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_stats_snapshot_buffer_usage_percent() -> TestResult {
    let snap = AuditStatsSnapshot {
        total_logged: 0,
        success_count: 0,
        failure_count: 0,
        current_entries: 50,
        capacity: 100,
        has_wrapped: false,
    };
    if snap.buffer_usage_percent() != 50.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_stats_snapshot_buffer_usage_percent_zero_capacity() -> TestResult {
    let snap = AuditStatsSnapshot {
        total_logged: 0,
        success_count: 0,
        failure_count: 0,
        current_entries: 0,
        capacity: 0,
        has_wrapped: false,
    };
    if snap.buffer_usage_percent() != 0.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_stats_snapshot_display() -> TestResult {
    let snap = AuditStatsSnapshot {
        total_logged: 100,
        success_count: 80,
        failure_count: 20,
        current_entries: 50,
        capacity: 1000,
        has_wrapped: false,
    };
    let display = alloc::format!("{}", snap);
    if !display.contains("total:100") {
        return TestResult::Fail;
    }
    if !display.contains("ok:80") {
        return TestResult::Fail;
    }
    if !display.contains("fail:20") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_stats_snapshot_default() -> TestResult {
    let snap = AuditStatsSnapshot::default();
    if snap.total_logged != 0 {
        return TestResult::Fail;
    }
    if snap.success_count != 0 {
        return TestResult::Fail;
    }
    if snap.failure_count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_capacity() -> TestResult {
    if audit_capacity() == 0 {
        return TestResult::Fail;
    }
    if audit_capacity() != MAX_LOG_ENTRIES {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_log_entries_constant() -> TestResult {
    if MAX_LOG_ENTRIES == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_clear_log() -> TestResult {
    clear_log();
    if !is_empty() {
        return TestResult::Fail;
    }
    if log_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_raw() -> TestResult {
    clear_log();
    reset_stats();
    log_raw(100, "test_action", Some(Capability::Admin), 12345, true);
    if log_count() != 1 {
        return TestResult::Fail;
    }
    if is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_use_with_token() -> TestResult {
    clear_log();
    reset_stats();
    let tok = CapabilityToken {
        owner_module: 42,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 99999,
        signature: [0u8; 64],
        ..super::fixtures::zero_token()
    };
    log_use(&tok, "token_test", Some(Capability::Admin), true);
    if log_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_success() -> TestResult {
    clear_log();
    reset_stats();
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Debug],
        expires_at_ms: None,
        nonce: 1,
        signature: [0u8; 64],
        ..super::fixtures::zero_token()
    };
    log_success(&tok, "success_action", Some(Capability::Debug));
    let entries = get_successes();
    if entries.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_failure() -> TestResult {
    clear_log();
    reset_stats();
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Debug],
        expires_at_ms: None,
        nonce: 1,
        signature: [0u8; 64],
        ..super::fixtures::zero_token()
    };
    log_failure(&tok, "failure_action", Some(Capability::Debug));
    let entries = get_failures();
    if entries.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_log_returns_entries() -> TestResult {
    clear_log();
    log_raw(1, "action1", None, 1, true);
    log_raw(2, "action2", None, 2, false);
    let log = get_log();
    if log.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_recent() -> TestResult {
    clear_log();
    for i in 0..10 {
        log_raw(i, "action", None, i, true);
    }
    let recent = get_recent(3);
    if recent.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_recent_more_than_available() -> TestResult {
    clear_log();
    log_raw(1, "action", None, 1, true);
    let recent = get_recent(100);
    if recent.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_stats() -> TestResult {
    clear_log();
    reset_stats();
    log_raw(1, "action", None, 1, true);
    log_raw(2, "action", None, 2, false);
    let stats = get_stats();
    if stats.total_logged != 2 {
        return TestResult::Fail;
    }
    if stats.success_count != 1 {
        return TestResult::Fail;
    }
    if stats.failure_count != 1 {
        return TestResult::Fail;
    }
    if stats.current_entries != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reset_stats() -> TestResult {
    log_raw(1, "action", None, 1, true);
    reset_stats();
    let stats = get_stats();
    if stats.total_logged != 0 {
        return TestResult::Fail;
    }
    if stats.success_count != 0 {
        return TestResult::Fail;
    }
    if stats.failure_count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_by_module() -> TestResult {
    clear_log();
    log_raw(100, "action", None, 1, true);
    log_raw(200, "action", None, 2, true);
    log_raw(100, "action2", None, 3, false);
    let entries = get_by_module(100);
    if entries.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_by_action() -> TestResult {
    clear_log();
    log_raw(1, "read", None, 1, true);
    log_raw(2, "write", None, 2, true);
    log_raw(3, "read", None, 3, true);
    let entries = get_by_action("read");
    if entries.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_by_capability() -> TestResult {
    clear_log();
    log_raw(1, "action", Some(Capability::Admin), 1, true);
    log_raw(2, "action", Some(Capability::Debug), 2, true);
    log_raw(3, "action", Some(Capability::Admin), 3, true);
    let entries = get_by_capability(Capability::Admin);
    if entries.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_successes() -> TestResult {
    clear_log();
    log_raw(1, "action", None, 1, true);
    log_raw(2, "action", None, 2, false);
    log_raw(3, "action", None, 3, true);
    let entries = get_successes();
    if entries.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_failures() -> TestResult {
    clear_log();
    log_raw(1, "action", None, 1, true);
    log_raw(2, "action", None, 2, false);
    log_raw(3, "action", None, 3, false);
    let entries = get_failures();
    if entries.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
