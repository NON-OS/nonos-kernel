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
fn test_supervisor_policy_default_restart_on_degraded() {
    let policy = supervisor::SupervisorPolicy::default();
    assert!(policy.restart_on_degraded);
}

#[test]
fn test_supervisor_policy_default_restart_on_stopped() {
    let policy = supervisor::SupervisorPolicy::default();
    assert!(policy.restart_on_stopped);
}

#[test]
fn test_supervisor_policy_default_restart_cooldown_ms() {
    let policy = supervisor::SupervisorPolicy::default();
    assert_eq!(policy.restart_cooldown_ms, 5_000);
}

#[test]
fn test_supervisor_policy_default_max_restarts_per_minute() {
    let policy = supervisor::SupervisorPolicy::default();
    assert_eq!(policy.max_restarts_per_minute, 10);
}

#[test]
fn test_supervisor_policy_clone() {
    let policy = supervisor::SupervisorPolicy::default();
    let cloned = policy.clone();
    assert_eq!(policy.restart_on_degraded, cloned.restart_on_degraded);
    assert_eq!(policy.restart_on_stopped, cloned.restart_on_stopped);
    assert_eq!(policy.restart_cooldown_ms, cloned.restart_cooldown_ms);
    assert_eq!(policy.max_restarts_per_minute, cloned.max_restarts_per_minute);
}

#[test]
fn test_supervisor_policy_debug() {
    let policy = supervisor::SupervisorPolicy::default();
    let debug_str = alloc::format!("{:?}", policy);
    assert!(debug_str.contains("SupervisorPolicy"));
}

#[test]
fn test_supervisor_policy_custom_restart_on_degraded_false() {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: false,
        ..Default::default()
    };
    assert!(!policy.restart_on_degraded);
}

#[test]
fn test_supervisor_policy_custom_restart_on_stopped_false() {
    let policy = supervisor::SupervisorPolicy {
        restart_on_stopped: false,
        ..Default::default()
    };
    assert!(!policy.restart_on_stopped);
}

#[test]
fn test_supervisor_policy_custom_restart_cooldown_ms() {
    let policy = supervisor::SupervisorPolicy {
        restart_cooldown_ms: 10_000,
        ..Default::default()
    };
    assert_eq!(policy.restart_cooldown_ms, 10_000);
}

#[test]
fn test_supervisor_policy_custom_max_restarts_per_minute() {
    let policy = supervisor::SupervisorPolicy {
        max_restarts_per_minute: 5,
        ..Default::default()
    };
    assert_eq!(policy.max_restarts_per_minute, 5);
}

#[test]
fn test_supervisor_policy_all_custom() {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: false,
        restart_on_stopped: false,
        restart_cooldown_ms: 1_000,
        max_restarts_per_minute: 3,
    };
    assert!(!policy.restart_on_degraded);
    assert!(!policy.restart_on_stopped);
    assert_eq!(policy.restart_cooldown_ms, 1_000);
    assert_eq!(policy.max_restarts_per_minute, 3);
}

#[test]
fn test_supervisor_policy_zero_cooldown() {
    let policy = supervisor::SupervisorPolicy {
        restart_cooldown_ms: 0,
        ..Default::default()
    };
    assert_eq!(policy.restart_cooldown_ms, 0);
}

#[test]
fn test_supervisor_policy_zero_max_restarts() {
    let policy = supervisor::SupervisorPolicy {
        max_restarts_per_minute: 0,
        ..Default::default()
    };
    assert_eq!(policy.max_restarts_per_minute, 0);
}

#[test]
fn test_supervisor_policy_large_cooldown() {
    let policy = supervisor::SupervisorPolicy {
        restart_cooldown_ms: 60_000,
        ..Default::default()
    };
    assert_eq!(policy.restart_cooldown_ms, 60_000);
}

#[test]
fn test_supervisor_policy_large_max_restarts() {
    let policy = supervisor::SupervisorPolicy {
        max_restarts_per_minute: 100,
        ..Default::default()
    };
    assert_eq!(policy.max_restarts_per_minute, 100);
}

#[test]
fn test_supervisor_policy_both_restart_flags_true() {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: true,
        restart_on_stopped: true,
        ..Default::default()
    };
    assert!(policy.restart_on_degraded);
    assert!(policy.restart_on_stopped);
}

#[test]
fn test_supervisor_policy_both_restart_flags_false() {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: false,
        restart_on_stopped: false,
        ..Default::default()
    };
    assert!(!policy.restart_on_degraded);
    assert!(!policy.restart_on_stopped);
}

#[test]
fn test_supervisor_policy_mixed_restart_flags() {
    let policy1 = supervisor::SupervisorPolicy {
        restart_on_degraded: true,
        restart_on_stopped: false,
        ..Default::default()
    };
    assert!(policy1.restart_on_degraded);
    assert!(!policy1.restart_on_stopped);

    let policy2 = supervisor::SupervisorPolicy {
        restart_on_degraded: false,
        restart_on_stopped: true,
        ..Default::default()
    };
    assert!(!policy2.restart_on_degraded);
    assert!(policy2.restart_on_stopped);
}

#[test]
fn test_supervisor_policy_debug_contains_fields() {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: true,
        restart_on_stopped: false,
        restart_cooldown_ms: 12345,
        max_restarts_per_minute: 42,
    };
    let debug_str = alloc::format!("{:?}", policy);
    assert!(debug_str.contains("restart_on_degraded"));
    assert!(debug_str.contains("restart_on_stopped"));
    assert!(debug_str.contains("restart_cooldown_ms"));
    assert!(debug_str.contains("max_restarts_per_minute"));
}

#[test]
fn test_supervisor_register_and_unregister() {
    let policy = supervisor::SupervisorPolicy::default();
    supervisor::register("test_capsule_supervisor", policy);
    supervisor::unregister("test_capsule_supervisor");
}

#[test]
fn test_supervisor_register_custom_policy() {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: false,
        restart_on_stopped: true,
        restart_cooldown_ms: 2000,
        max_restarts_per_minute: 5,
    };
    supervisor::register("custom_policy_capsule", policy);
    supervisor::unregister("custom_policy_capsule");
}

#[test]
fn test_supervisor_restart_stats_none_for_unknown() {
    let result = supervisor::restart_stats("nonexistent_capsule_xyz");
    assert!(result.is_none());
}

#[test]
fn test_supervisor_restart_stats_after_register() {
    let policy = supervisor::SupervisorPolicy::default();
    supervisor::register("stats_test_capsule", policy);
    let stats = supervisor::restart_stats("stats_test_capsule");
    assert!(stats.is_some());
    let (count, _last) = stats.unwrap();
    assert_eq!(count, 0);
    supervisor::unregister("stats_test_capsule");
}

#[test]
fn test_supervisor_register_multiple() {
    let policy = supervisor::SupervisorPolicy::default();
    supervisor::register("multi_capsule_1", policy.clone());
    supervisor::register("multi_capsule_2", policy.clone());
    supervisor::register("multi_capsule_3", policy);
    supervisor::unregister("multi_capsule_1");
    supervisor::unregister("multi_capsule_2");
    supervisor::unregister("multi_capsule_3");
}

#[test]
fn test_supervisor_unregister_nonexistent() {
    supervisor::unregister("definitely_not_registered_capsule");
}

#[test]
fn test_supervisor_policy_max_values() {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: true,
        restart_on_stopped: true,
        restart_cooldown_ms: u64::MAX,
        max_restarts_per_minute: u32::MAX,
    };
    assert_eq!(policy.restart_cooldown_ms, u64::MAX);
    assert_eq!(policy.max_restarts_per_minute, u32::MAX);
}
