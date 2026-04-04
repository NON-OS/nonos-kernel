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

use crate::runtime::*;

#[test]
fn test_isolation_policy_default_inbox_capacity() {
    let policy = isolation::IsolationPolicy::default();
    assert_eq!(policy.inbox_capacity, 1024);
}

#[test]
fn test_isolation_policy_default_max_msg_bytes() {
    let policy = isolation::IsolationPolicy::default();
    assert_eq!(policy.max_msg_bytes, 1 << 20);
}

#[test]
fn test_isolation_policy_default_max_bytes_per_sec() {
    let policy = isolation::IsolationPolicy::default();
    assert_eq!(policy.max_bytes_per_sec, 4 << 20);
}

#[test]
fn test_isolation_policy_default_heartbeat_interval_ms() {
    let policy = isolation::IsolationPolicy::default();
    assert_eq!(policy.heartbeat_interval_ms, 2_000);
}

#[test]
fn test_isolation_policy_clone() {
    let policy = isolation::IsolationPolicy::default();
    let cloned = policy.clone();
    assert_eq!(policy.inbox_capacity, cloned.inbox_capacity);
    assert_eq!(policy.max_msg_bytes, cloned.max_msg_bytes);
    assert_eq!(policy.max_bytes_per_sec, cloned.max_bytes_per_sec);
    assert_eq!(policy.heartbeat_interval_ms, cloned.heartbeat_interval_ms);
}

#[test]
fn test_isolation_policy_debug() {
    let policy = isolation::IsolationPolicy::default();
    let debug_str = alloc::format!("{:?}", policy);
    assert!(debug_str.contains("IsolationPolicy"));
}

#[test]
fn test_isolation_policy_custom_inbox_capacity() {
    let policy = isolation::IsolationPolicy {
        inbox_capacity: 2048,
        ..Default::default()
    };
    assert_eq!(policy.inbox_capacity, 2048);
}

#[test]
fn test_isolation_policy_custom_max_msg_bytes() {
    let policy = isolation::IsolationPolicy {
        max_msg_bytes: 512 * 1024,
        ..Default::default()
    };
    assert_eq!(policy.max_msg_bytes, 524288);
}

#[test]
fn test_isolation_policy_custom_max_bytes_per_sec() {
    let policy = isolation::IsolationPolicy {
        max_bytes_per_sec: 8 << 20,
        ..Default::default()
    };
    assert_eq!(policy.max_bytes_per_sec, 8388608);
}

#[test]
fn test_isolation_policy_custom_heartbeat_interval_ms() {
    let policy = isolation::IsolationPolicy {
        heartbeat_interval_ms: 5_000,
        ..Default::default()
    };
    assert_eq!(policy.heartbeat_interval_ms, 5_000);
}

#[test]
fn test_isolation_policy_all_custom() {
    let policy = isolation::IsolationPolicy {
        inbox_capacity: 512,
        max_msg_bytes: 256 * 1024,
        max_bytes_per_sec: 1 << 20,
        heartbeat_interval_ms: 1_000,
    };
    assert_eq!(policy.inbox_capacity, 512);
    assert_eq!(policy.max_msg_bytes, 262144);
    assert_eq!(policy.max_bytes_per_sec, 1048576);
    assert_eq!(policy.heartbeat_interval_ms, 1_000);
}

#[test]
fn test_isolation_state_new() {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("test_capsule", policy);
    assert_eq!(state.capsule_name, "test_capsule");
}

#[test]
fn test_isolation_state_dropped_initial() {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("test", policy);
    assert_eq!(state.dropped(), 0);
}

#[test]
fn test_isolation_state_status_format() {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("my_capsule", policy);
    let status = state.status();
    assert!(status.contains("iso[capsule=my_capsule"));
    assert!(status.contains("used="));
    assert!(status.contains("limit="));
    assert!(status.contains("dropped="));
}

#[test]
fn test_isolation_state_charge_message_small() {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("test", policy);
    let result = state.charge_message(100);
    assert!(result.is_ok());
}

#[test]
fn test_isolation_state_charge_message_at_limit() {
    let policy = isolation::IsolationPolicy {
        max_msg_bytes: 1024,
        ..Default::default()
    };
    let state = isolation::IsolationState::new("test", policy);
    let result = state.charge_message(1024);
    assert!(result.is_ok());
}

#[test]
fn test_isolation_state_charge_message_over_limit() {
    let policy = isolation::IsolationPolicy {
        max_msg_bytes: 1024,
        ..Default::default()
    };
    let state = isolation::IsolationState::new("test", policy);
    let result = state.charge_message(1025);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "isolation: message too large");
}

#[test]
fn test_isolation_state_dropped_increments_on_large_message() {
    let policy = isolation::IsolationPolicy {
        max_msg_bytes: 100,
        ..Default::default()
    };
    let state = isolation::IsolationState::new("test", policy);
    let _ = state.charge_message(200);
    assert_eq!(state.dropped(), 1);
}

#[test]
fn test_isolation_state_set_enforced() {
    let policy = isolation::IsolationPolicy::default();
    let mut state = isolation::IsolationState::new("test", policy);
    state.set_enforced(false);
    let status = state.status();
    assert!(status.contains("test"));
}

#[test]
fn test_isolation_state_multiple_charge_messages() {
    let policy = isolation::IsolationPolicy {
        max_bytes_per_sec: 1000,
        max_msg_bytes: 500,
        ..Default::default()
    };
    let state = isolation::IsolationState::new("test", policy);
    assert!(state.charge_message(100).is_ok());
    assert!(state.charge_message(100).is_ok());
    assert!(state.charge_message(100).is_ok());
}

#[test]
fn test_isolation_policy_megabyte_limits() {
    let policy = isolation::IsolationPolicy {
        max_msg_bytes: 1 << 20,
        max_bytes_per_sec: 4 << 20,
        ..Default::default()
    };
    assert_eq!(policy.max_msg_bytes, 1048576);
    assert_eq!(policy.max_bytes_per_sec, 4194304);
}

#[test]
fn test_isolation_state_capsule_name_static() {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("static_name", policy);
    assert_eq!(state.capsule_name, "static_name");
}

#[test]
fn test_isolation_state_status_contains_capsule_name() {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("unique_capsule_name", policy);
    let status = state.status();
    assert!(status.contains("unique_capsule_name"));
}

#[test]
fn test_isolation_state_status_contains_limit() {
    let policy = isolation::IsolationPolicy {
        max_bytes_per_sec: 12345678,
        ..Default::default()
    };
    let state = isolation::IsolationState::new("test", policy);
    let status = state.status();
    assert!(status.contains("12345678"));
}

#[test]
fn test_isolation_policy_zero_inbox_capacity() {
    let policy = isolation::IsolationPolicy {
        inbox_capacity: 0,
        ..Default::default()
    };
    assert_eq!(policy.inbox_capacity, 0);
}

#[test]
fn test_isolation_policy_large_heartbeat_interval() {
    let policy = isolation::IsolationPolicy {
        heartbeat_interval_ms: 60_000,
        ..Default::default()
    };
    assert_eq!(policy.heartbeat_interval_ms, 60_000);
}

#[test]
fn test_isolation_state_charge_zero_bytes() {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("test", policy);
    let result = state.charge_message(0);
    assert!(result.is_ok());
}

#[test]
fn test_isolation_state_multiple_dropped() {
    let policy = isolation::IsolationPolicy {
        max_msg_bytes: 10,
        ..Default::default()
    };
    let state = isolation::IsolationState::new("test", policy);
    let _ = state.charge_message(100);
    let _ = state.charge_message(100);
    let _ = state.charge_message(100);
    assert_eq!(state.dropped(), 3);
}
