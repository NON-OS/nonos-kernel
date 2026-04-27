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

pub(crate) fn test_supervisor_policy_default_restart_on_degraded() -> TestResult {
    let policy = supervisor::SupervisorPolicy::default();
    if !policy.restart_on_degraded {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_default_restart_on_stopped() -> TestResult {
    let policy = supervisor::SupervisorPolicy::default();
    if !policy.restart_on_stopped {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_default_restart_cooldown_ms() -> TestResult {
    let policy = supervisor::SupervisorPolicy::default();
    if policy.restart_cooldown_ms != 5_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_default_max_restarts_per_minute() -> TestResult {
    let policy = supervisor::SupervisorPolicy::default();
    if policy.max_restarts_per_minute != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_clone() -> TestResult {
    let policy = supervisor::SupervisorPolicy::default();
    let cloned = policy.clone();
    if policy.restart_on_degraded != cloned.restart_on_degraded {
        return TestResult::Fail;
    }
    if policy.restart_on_stopped != cloned.restart_on_stopped {
        return TestResult::Fail;
    }
    if policy.restart_cooldown_ms != cloned.restart_cooldown_ms {
        return TestResult::Fail;
    }
    if policy.max_restarts_per_minute != cloned.max_restarts_per_minute {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_debug() -> TestResult {
    let policy = supervisor::SupervisorPolicy::default();
    let debug_str = alloc::format!("{:?}", policy);
    if !debug_str.contains("SupervisorPolicy") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_custom_restart_on_degraded_false() -> TestResult {
    let policy = supervisor::SupervisorPolicy { restart_on_degraded: false, ..Default::default() };
    if policy.restart_on_degraded {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_custom_restart_on_stopped_false() -> TestResult {
    let policy = supervisor::SupervisorPolicy { restart_on_stopped: false, ..Default::default() };
    if policy.restart_on_stopped {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_custom_restart_cooldown_ms() -> TestResult {
    let policy = supervisor::SupervisorPolicy { restart_cooldown_ms: 10_000, ..Default::default() };
    if policy.restart_cooldown_ms != 10_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_custom_max_restarts_per_minute() -> TestResult {
    let policy = supervisor::SupervisorPolicy { max_restarts_per_minute: 5, ..Default::default() };
    if policy.max_restarts_per_minute != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_all_custom() -> TestResult {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: false,
        restart_on_stopped: false,
        restart_cooldown_ms: 1_000,
        max_restarts_per_minute: 3,
    };
    if policy.restart_on_degraded {
        return TestResult::Fail;
    }
    if policy.restart_on_stopped {
        return TestResult::Fail;
    }
    if policy.restart_cooldown_ms != 1_000 {
        return TestResult::Fail;
    }
    if policy.max_restarts_per_minute != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_zero_cooldown() -> TestResult {
    let policy = supervisor::SupervisorPolicy { restart_cooldown_ms: 0, ..Default::default() };
    if policy.restart_cooldown_ms != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_zero_max_restarts() -> TestResult {
    let policy = supervisor::SupervisorPolicy { max_restarts_per_minute: 0, ..Default::default() };
    if policy.max_restarts_per_minute != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_large_cooldown() -> TestResult {
    let policy = supervisor::SupervisorPolicy { restart_cooldown_ms: 60_000, ..Default::default() };
    if policy.restart_cooldown_ms != 60_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_large_max_restarts() -> TestResult {
    let policy =
        supervisor::SupervisorPolicy { max_restarts_per_minute: 100, ..Default::default() };
    if policy.max_restarts_per_minute != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_both_restart_flags_true() -> TestResult {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: true,
        restart_on_stopped: true,
        ..Default::default()
    };
    if !policy.restart_on_degraded {
        return TestResult::Fail;
    }
    if !policy.restart_on_stopped {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_both_restart_flags_false() -> TestResult {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: false,
        restart_on_stopped: false,
        ..Default::default()
    };
    if policy.restart_on_degraded {
        return TestResult::Fail;
    }
    if policy.restart_on_stopped {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_mixed_restart_flags() -> TestResult {
    let policy1 = supervisor::SupervisorPolicy {
        restart_on_degraded: true,
        restart_on_stopped: false,
        ..Default::default()
    };
    if !policy1.restart_on_degraded {
        return TestResult::Fail;
    }
    if policy1.restart_on_stopped {
        return TestResult::Fail;
    }

    let policy2 = supervisor::SupervisorPolicy {
        restart_on_degraded: false,
        restart_on_stopped: true,
        ..Default::default()
    };
    if policy2.restart_on_degraded {
        return TestResult::Fail;
    }
    if !policy2.restart_on_stopped {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_debug_contains_fields() -> TestResult {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: true,
        restart_on_stopped: false,
        restart_cooldown_ms: 12345,
        max_restarts_per_minute: 42,
    };
    let debug_str = alloc::format!("{:?}", policy);
    if !debug_str.contains("restart_on_degraded") {
        return TestResult::Fail;
    }
    if !debug_str.contains("restart_on_stopped") {
        return TestResult::Fail;
    }
    if !debug_str.contains("restart_cooldown_ms") {
        return TestResult::Fail;
    }
    if !debug_str.contains("max_restarts_per_minute") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_register_and_unregister() -> TestResult {
    let policy = supervisor::SupervisorPolicy::default();
    supervisor::register("test_capsule_supervisor", policy);
    supervisor::unregister("test_capsule_supervisor");
    TestResult::Pass
}

pub(crate) fn test_supervisor_register_custom_policy() -> TestResult {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: false,
        restart_on_stopped: true,
        restart_cooldown_ms: 2000,
        max_restarts_per_minute: 5,
    };
    supervisor::register("custom_policy_capsule", policy);
    supervisor::unregister("custom_policy_capsule");
    TestResult::Pass
}

pub(crate) fn test_supervisor_restart_stats_none_for_unknown() -> TestResult {
    let result = supervisor::restart_stats("nonexistent_capsule_xyz");
    if !result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_restart_stats_after_register() -> TestResult {
    let policy = supervisor::SupervisorPolicy::default();
    supervisor::register("stats_test_capsule", policy);
    let stats = supervisor::restart_stats("stats_test_capsule");
    if !stats.is_some() {
        return TestResult::Fail;
    }
    let (count, _last) = stats.unwrap();
    if count != 0 {
        return TestResult::Fail;
    }
    supervisor::unregister("stats_test_capsule");
    TestResult::Pass
}

pub(crate) fn test_supervisor_register_multiple() -> TestResult {
    let policy = supervisor::SupervisorPolicy::default();
    supervisor::register("multi_capsule_1", policy.clone());
    supervisor::register("multi_capsule_2", policy.clone());
    supervisor::register("multi_capsule_3", policy);
    supervisor::unregister("multi_capsule_1");
    supervisor::unregister("multi_capsule_2");
    supervisor::unregister("multi_capsule_3");
    TestResult::Pass
}

pub(crate) fn test_supervisor_unregister_nonexistent() -> TestResult {
    supervisor::unregister("definitely_not_registered_capsule");
    TestResult::Pass
}

pub(crate) fn test_supervisor_policy_max_values() -> TestResult {
    let policy = supervisor::SupervisorPolicy {
        restart_on_degraded: true,
        restart_on_stopped: true,
        restart_cooldown_ms: u64::MAX,
        max_restarts_per_minute: u32::MAX,
    };
    if policy.restart_cooldown_ms != u64::MAX {
        return TestResult::Fail;
    }
    if policy.max_restarts_per_minute != u32::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}
