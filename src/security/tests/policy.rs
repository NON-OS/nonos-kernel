// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::security::{SecureBootPolicy, set_policy, get_policy, is_enforcing};

#[test]
fn test_secure_boot_policy_disabled() {
    let policy = SecureBootPolicy::Disabled;
    assert_eq!(policy, SecureBootPolicy::Disabled);
}

#[test]
fn test_secure_boot_policy_permissive() {
    let policy = SecureBootPolicy::Permissive;
    assert_eq!(policy, SecureBootPolicy::Permissive);
}

#[test]
fn test_secure_boot_policy_enforcing() {
    let policy = SecureBootPolicy::Enforcing;
    assert_eq!(policy, SecureBootPolicy::Enforcing);
}

#[test]
fn test_secure_boot_policy_strict() {
    let policy = SecureBootPolicy::Strict;
    assert_eq!(policy, SecureBootPolicy::Strict);
}

#[test]
fn test_secure_boot_policy_equality() {
    assert_eq!(SecureBootPolicy::Disabled, SecureBootPolicy::Disabled);
    assert_ne!(SecureBootPolicy::Disabled, SecureBootPolicy::Permissive);
    assert_ne!(SecureBootPolicy::Enforcing, SecureBootPolicy::Strict);
}

#[test]
fn test_secure_boot_policy_clone() {
    let p1 = SecureBootPolicy::Enforcing;
    let p2 = p1.clone();
    assert_eq!(p1, p2);
}

#[test]
fn test_secure_boot_policy_copy() {
    let p1 = SecureBootPolicy::Strict;
    let p2 = p1;
    assert_eq!(p1, p2);
}

#[test]
fn test_set_policy_disabled() {
    set_policy(SecureBootPolicy::Disabled);
    assert_eq!(get_policy(), SecureBootPolicy::Disabled);
    assert!(!is_enforcing());
}

#[test]
fn test_set_policy_permissive() {
    set_policy(SecureBootPolicy::Permissive);
    assert_eq!(get_policy(), SecureBootPolicy::Permissive);
    assert!(!is_enforcing());
}

#[test]
fn test_set_policy_enforcing() {
    set_policy(SecureBootPolicy::Enforcing);
    assert_eq!(get_policy(), SecureBootPolicy::Enforcing);
    assert!(is_enforcing());
}

#[test]
fn test_set_policy_strict() {
    set_policy(SecureBootPolicy::Strict);
    assert_eq!(get_policy(), SecureBootPolicy::Strict);
    assert!(is_enforcing());
}

#[test]
fn test_get_policy() {
    let policy = get_policy();
    let _ = policy;
}

#[test]
fn test_is_enforcing() {
    let _ = is_enforcing();
}

#[test]
fn test_policy_transition_disabled_to_enforcing() {
    set_policy(SecureBootPolicy::Disabled);
    assert!(!is_enforcing());
    set_policy(SecureBootPolicy::Enforcing);
    assert!(is_enforcing());
}

#[test]
fn test_policy_transition_enforcing_to_disabled() {
    set_policy(SecureBootPolicy::Enforcing);
    assert!(is_enforcing());
    set_policy(SecureBootPolicy::Disabled);
    assert!(!is_enforcing());
}

#[test]
fn test_policy_transition_permissive_to_strict() {
    set_policy(SecureBootPolicy::Permissive);
    assert!(!is_enforcing());
    set_policy(SecureBootPolicy::Strict);
    assert!(is_enforcing());
}

#[test]
fn test_secure_boot_policy_all_variants() {
    let policies = [
        SecureBootPolicy::Disabled,
        SecureBootPolicy::Permissive,
        SecureBootPolicy::Enforcing,
        SecureBootPolicy::Strict,
    ];
    assert_eq!(policies.len(), 4);
}

#[test]
fn test_secure_boot_policy_all_unique() {
    let policies = [
        SecureBootPolicy::Disabled,
        SecureBootPolicy::Permissive,
        SecureBootPolicy::Enforcing,
        SecureBootPolicy::Strict,
    ];
    for i in 0..policies.len() {
        for j in (i + 1)..policies.len() {
            assert_ne!(policies[i], policies[j]);
        }
    }
}

#[test]
fn test_secure_boot_policy_debug() {
    let policy = SecureBootPolicy::Enforcing;
    let debug_str = alloc::format!("{:?}", policy);
    assert!(debug_str.contains("Enforcing"));
}

#[test]
fn test_enforcing_policies() {
    let enforcing_policies = [
        SecureBootPolicy::Enforcing,
        SecureBootPolicy::Strict,
    ];
    for policy in enforcing_policies {
        set_policy(policy);
        assert!(is_enforcing());
    }
}

#[test]
fn test_non_enforcing_policies() {
    let non_enforcing_policies = [
        SecureBootPolicy::Disabled,
        SecureBootPolicy::Permissive,
    ];
    for policy in non_enforcing_policies {
        set_policy(policy);
        assert!(!is_enforcing());
    }
}

#[test]
fn test_policy_roundtrip() {
    let original = get_policy();
    set_policy(SecureBootPolicy::Strict);
    assert_eq!(get_policy(), SecureBootPolicy::Strict);
    set_policy(original);
    assert_eq!(get_policy(), original);
}

#[test]
fn test_multiple_set_policy_calls() {
    set_policy(SecureBootPolicy::Disabled);
    set_policy(SecureBootPolicy::Permissive);
    set_policy(SecureBootPolicy::Enforcing);
    set_policy(SecureBootPolicy::Strict);
    assert_eq!(get_policy(), SecureBootPolicy::Strict);
}

#[test]
fn test_policy_idempotent() {
    set_policy(SecureBootPolicy::Enforcing);
    let first = is_enforcing();
    set_policy(SecureBootPolicy::Enforcing);
    let second = is_enforcing();
    assert_eq!(first, second);
}

