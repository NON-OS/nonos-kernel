// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Security policy management tests

extern crate alloc;

use crate::security::{get_policy, is_enforcing, set_policy, SecureBootPolicy};
use crate::test::framework::TestResult;
use alloc::format;

pub(crate) fn test_secure_boot_policy_disabled() -> TestResult {
    let policy = SecureBootPolicy::Disabled;
    if policy != SecureBootPolicy::Disabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_permissive() -> TestResult {
    let policy = SecureBootPolicy::Permissive;
    if policy != SecureBootPolicy::Permissive {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_enforcing() -> TestResult {
    let policy = SecureBootPolicy::Enforcing;
    if policy != SecureBootPolicy::Enforcing {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_strict() -> TestResult {
    let policy = SecureBootPolicy::Strict;
    if policy != SecureBootPolicy::Strict {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_equality() -> TestResult {
    if SecureBootPolicy::Disabled != SecureBootPolicy::Disabled {
        return TestResult::Fail;
    }
    if SecureBootPolicy::Disabled == SecureBootPolicy::Permissive {
        return TestResult::Fail;
    }
    if SecureBootPolicy::Enforcing == SecureBootPolicy::Strict {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_clone() -> TestResult {
    let p1 = SecureBootPolicy::Enforcing;
    let p2 = p1.clone();
    if p1 != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_copy() -> TestResult {
    let p1 = SecureBootPolicy::Strict;
    let p2 = p1;
    if p1 != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_policy_disabled() -> TestResult {
    set_policy(SecureBootPolicy::Disabled);
    if get_policy() != SecureBootPolicy::Disabled {
        return TestResult::Fail;
    }
    if is_enforcing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_policy_permissive() -> TestResult {
    set_policy(SecureBootPolicy::Permissive);
    if get_policy() != SecureBootPolicy::Permissive {
        return TestResult::Fail;
    }
    if is_enforcing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_policy_enforcing() -> TestResult {
    set_policy(SecureBootPolicy::Enforcing);
    if get_policy() != SecureBootPolicy::Enforcing {
        return TestResult::Fail;
    }
    if !is_enforcing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_policy_strict() -> TestResult {
    set_policy(SecureBootPolicy::Strict);
    if get_policy() != SecureBootPolicy::Strict {
        return TestResult::Fail;
    }
    if !is_enforcing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_policy() -> TestResult {
    let policy = get_policy();
    let _ = policy;
    TestResult::Pass
}

pub(crate) fn test_is_enforcing() -> TestResult {
    let _ = is_enforcing();
    TestResult::Pass
}

pub(crate) fn test_policy_transition_disabled_to_enforcing() -> TestResult {
    set_policy(SecureBootPolicy::Disabled);
    if is_enforcing() {
        return TestResult::Fail;
    }
    set_policy(SecureBootPolicy::Enforcing);
    if !is_enforcing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_transition_enforcing_to_disabled() -> TestResult {
    set_policy(SecureBootPolicy::Enforcing);
    if !is_enforcing() {
        return TestResult::Fail;
    }
    set_policy(SecureBootPolicy::Disabled);
    if is_enforcing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_transition_permissive_to_strict() -> TestResult {
    set_policy(SecureBootPolicy::Permissive);
    if is_enforcing() {
        return TestResult::Fail;
    }
    set_policy(SecureBootPolicy::Strict);
    if !is_enforcing() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_all_variants() -> TestResult {
    let policies = [
        SecureBootPolicy::Disabled,
        SecureBootPolicy::Permissive,
        SecureBootPolicy::Enforcing,
        SecureBootPolicy::Strict,
    ];
    if policies.len() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_all_unique() -> TestResult {
    let policies = [
        SecureBootPolicy::Disabled,
        SecureBootPolicy::Permissive,
        SecureBootPolicy::Enforcing,
        SecureBootPolicy::Strict,
    ];
    for i in 0..policies.len() {
        for j in (i + 1)..policies.len() {
            if policies[i] == policies[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_secure_boot_policy_debug() -> TestResult {
    let policy = SecureBootPolicy::Enforcing;
    let debug_str = format!("{:?}", policy);
    if !debug_str.contains("Enforcing") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enforcing_policies() -> TestResult {
    let enforcing_policies = [SecureBootPolicy::Enforcing, SecureBootPolicy::Strict];
    for policy in enforcing_policies {
        set_policy(policy);
        if !is_enforcing() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_non_enforcing_policies() -> TestResult {
    let non_enforcing_policies = [SecureBootPolicy::Disabled, SecureBootPolicy::Permissive];
    for policy in non_enforcing_policies {
        set_policy(policy);
        if is_enforcing() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_policy_roundtrip() -> TestResult {
    let original = get_policy();
    set_policy(SecureBootPolicy::Strict);
    if get_policy() != SecureBootPolicy::Strict {
        return TestResult::Fail;
    }
    set_policy(original);
    if get_policy() != original {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiple_set_policy_calls() -> TestResult {
    set_policy(SecureBootPolicy::Disabled);
    set_policy(SecureBootPolicy::Permissive);
    set_policy(SecureBootPolicy::Enforcing);
    set_policy(SecureBootPolicy::Strict);
    if get_policy() != SecureBootPolicy::Strict {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_idempotent() -> TestResult {
    set_policy(SecureBootPolicy::Enforcing);
    let first = is_enforcing();
    set_policy(SecureBootPolicy::Enforcing);
    let second = is_enforcing();
    if first != second {
        return TestResult::Fail;
    }
    TestResult::Pass
}
