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
use crate::test::framework::TestResult;

pub(crate) fn test_isolation_policy_default_inbox_capacity() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    if policy.inbox_capacity != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_default_max_msg_bytes() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    if policy.max_msg_bytes != 1 << 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_default_max_bytes_per_sec() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    if policy.max_bytes_per_sec != 4 << 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_default_heartbeat_interval_ms() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    if policy.heartbeat_interval_ms != 2_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_clone() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    let cloned = policy.clone();
    if policy.inbox_capacity != cloned.inbox_capacity {
        return TestResult::Fail;
    }
    if policy.max_msg_bytes != cloned.max_msg_bytes {
        return TestResult::Fail;
    }
    if policy.max_bytes_per_sec != cloned.max_bytes_per_sec {
        return TestResult::Fail;
    }
    if policy.heartbeat_interval_ms != cloned.heartbeat_interval_ms {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_debug() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    let debug_str = alloc::format!("{:?}", policy);
    if !debug_str.contains("IsolationPolicy") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_custom_inbox_capacity() -> TestResult {
    let policy = isolation::IsolationPolicy { inbox_capacity: 2048, ..Default::default() };
    if policy.inbox_capacity != 2048 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_custom_max_msg_bytes() -> TestResult {
    let policy = isolation::IsolationPolicy { max_msg_bytes: 512 * 1024, ..Default::default() };
    if policy.max_msg_bytes != 524288 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_custom_max_bytes_per_sec() -> TestResult {
    let policy = isolation::IsolationPolicy { max_bytes_per_sec: 8 << 20, ..Default::default() };
    if policy.max_bytes_per_sec != 8388608 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_custom_heartbeat_interval_ms() -> TestResult {
    let policy = isolation::IsolationPolicy { heartbeat_interval_ms: 5_000, ..Default::default() };
    if policy.heartbeat_interval_ms != 5_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_all_custom() -> TestResult {
    let policy = isolation::IsolationPolicy {
        inbox_capacity: 512,
        max_msg_bytes: 256 * 1024,
        max_bytes_per_sec: 1 << 20,
        heartbeat_interval_ms: 1_000,
    };
    if policy.inbox_capacity != 512 {
        return TestResult::Fail;
    }
    if policy.max_msg_bytes != 262144 {
        return TestResult::Fail;
    }
    if policy.max_bytes_per_sec != 1048576 {
        return TestResult::Fail;
    }
    if policy.heartbeat_interval_ms != 1_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_new() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("test_capsule", policy);
    if state.capsule_name != "test_capsule" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_dropped_initial() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("test", policy);
    if state.dropped() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_status_format() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("my_capsule", policy);
    let status = state.status();
    if !status.contains("iso[capsule=my_capsule") {
        return TestResult::Fail;
    }
    if !status.contains("used=") {
        return TestResult::Fail;
    }
    if !status.contains("limit=") {
        return TestResult::Fail;
    }
    if !status.contains("dropped=") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_charge_message_small() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("test", policy);
    let result = state.charge_message(100);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_charge_message_at_limit() -> TestResult {
    let policy = isolation::IsolationPolicy { max_msg_bytes: 1024, ..Default::default() };
    let state = isolation::IsolationState::new("test", policy);
    let result = state.charge_message(1024);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_charge_message_over_limit() -> TestResult {
    let policy = isolation::IsolationPolicy { max_msg_bytes: 1024, ..Default::default() };
    let state = isolation::IsolationState::new("test", policy);
    let result = state.charge_message(1025);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "isolation: message too large" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_dropped_increments_on_large_message() -> TestResult {
    let policy = isolation::IsolationPolicy { max_msg_bytes: 100, ..Default::default() };
    let state = isolation::IsolationState::new("test", policy);
    let _ = state.charge_message(200);
    if state.dropped() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_set_enforced() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    let mut state = isolation::IsolationState::new("test", policy);
    state.set_enforced(false);
    let status = state.status();
    if !status.contains("test") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_multiple_charge_messages() -> TestResult {
    let policy = isolation::IsolationPolicy {
        max_bytes_per_sec: 1000,
        max_msg_bytes: 500,
        ..Default::default()
    };
    let state = isolation::IsolationState::new("test", policy);
    if !state.charge_message(100).is_ok() {
        return TestResult::Fail;
    }
    if !state.charge_message(100).is_ok() {
        return TestResult::Fail;
    }
    if !state.charge_message(100).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_megabyte_limits() -> TestResult {
    let policy = isolation::IsolationPolicy {
        max_msg_bytes: 1 << 20,
        max_bytes_per_sec: 4 << 20,
        ..Default::default()
    };
    if policy.max_msg_bytes != 1048576 {
        return TestResult::Fail;
    }
    if policy.max_bytes_per_sec != 4194304 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_capsule_name_static() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("static_name", policy);
    if state.capsule_name != "static_name" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_status_contains_capsule_name() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("unique_capsule_name", policy);
    let status = state.status();
    if !status.contains("unique_capsule_name") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_status_contains_limit() -> TestResult {
    let policy = isolation::IsolationPolicy { max_bytes_per_sec: 12345678, ..Default::default() };
    let state = isolation::IsolationState::new("test", policy);
    let status = state.status();
    if !status.contains("12345678") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_zero_inbox_capacity() -> TestResult {
    let policy = isolation::IsolationPolicy { inbox_capacity: 0, ..Default::default() };
    if policy.inbox_capacity != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_policy_large_heartbeat_interval() -> TestResult {
    let policy = isolation::IsolationPolicy { heartbeat_interval_ms: 60_000, ..Default::default() };
    if policy.heartbeat_interval_ms != 60_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_charge_zero_bytes() -> TestResult {
    let policy = isolation::IsolationPolicy::default();
    let state = isolation::IsolationState::new("test", policy);
    let result = state.charge_message(0);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isolation_state_multiple_dropped() -> TestResult {
    let policy = isolation::IsolationPolicy { max_msg_bytes: 10, ..Default::default() };
    let state = isolation::IsolationState::new("test", policy);
    let _ = state.charge_message(100);
    let _ = state.charge_message(100);
    let _ = state.charge_message(100);
    if state.dropped() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
