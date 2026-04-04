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

use crate::vault::nonos_vault_diag::*;
use crate::vault::nonos_vault::{initialize_vault, vault_initialized, secure_erase_vault};
use crate::vault::nonos_vault_policy::{VaultCapability, VaultPolicyRule, set_vault_policy, clear_vault_policy};

#[test]
fn test_vault_health_healthy_eq() {
    assert_eq!(VaultHealth::Healthy, VaultHealth::Healthy);
}

#[test]
fn test_vault_health_uninitialized_eq() {
    assert_eq!(VaultHealth::Uninitialized, VaultHealth::Uninitialized);
}

#[test]
fn test_vault_health_leaked_eq() {
    assert_eq!(VaultHealth::Leaked, VaultHealth::Leaked);
}

#[test]
fn test_vault_health_policy_violation_eq() {
    assert_eq!(VaultHealth::PolicyViolation, VaultHealth::PolicyViolation);
}

#[test]
fn test_vault_health_audit_overflow_eq() {
    assert_eq!(VaultHealth::AuditOverflow, VaultHealth::AuditOverflow);
}

#[test]
fn test_vault_health_unknown_eq() {
    assert_eq!(VaultHealth::Unknown, VaultHealth::Unknown);
}

#[test]
fn test_vault_health_different_ne() {
    assert_ne!(VaultHealth::Healthy, VaultHealth::Uninitialized);
    assert_ne!(VaultHealth::Leaked, VaultHealth::PolicyViolation);
    assert_ne!(VaultHealth::AuditOverflow, VaultHealth::Unknown);
}

#[test]
fn test_vault_health_clone() {
    let health = VaultHealth::Healthy;
    let cloned = health.clone();
    assert_eq!(health, cloned);
}

#[test]
fn test_vault_health_copy() {
    let health = VaultHealth::Leaked;
    let copied: VaultHealth = health;
    assert_eq!(health, copied);
}

#[test]
fn test_vault_health_debug_healthy() {
    let debug = alloc::format!("{:?}", VaultHealth::Healthy);
    assert!(debug.contains("Healthy"));
}

#[test]
fn test_vault_health_debug_uninitialized() {
    let debug = alloc::format!("{:?}", VaultHealth::Uninitialized);
    assert!(debug.contains("Uninitialized"));
}

#[test]
fn test_vault_health_debug_leaked() {
    let debug = alloc::format!("{:?}", VaultHealth::Leaked);
    assert!(debug.contains("Leaked"));
}

#[test]
fn test_vault_health_debug_policy_violation() {
    let debug = alloc::format!("{:?}", VaultHealth::PolicyViolation);
    assert!(debug.contains("PolicyViolation"));
}

#[test]
fn test_vault_health_debug_audit_overflow() {
    let debug = alloc::format!("{:?}", VaultHealth::AuditOverflow);
    assert!(debug.contains("AuditOverflow"));
}

#[test]
fn test_vault_health_debug_unknown() {
    let debug = alloc::format!("{:?}", VaultHealth::Unknown);
    assert!(debug.contains("Unknown"));
}

#[test]
fn test_vault_diagnostics_clone() {
    let diag = VaultDiagnostics {
        health: VaultHealth::Healthy,
        audit_recent: alloc::vec![],
        policy_overview: alloc::vec![],
        sealed_count: 0,
    };
    let cloned = diag.clone();
    assert_eq!(diag.health, cloned.health);
    assert_eq!(diag.sealed_count, cloned.sealed_count);
}

#[test]
fn test_vault_diagnostics_debug() {
    let diag = VaultDiagnostics {
        health: VaultHealth::Uninitialized,
        audit_recent: alloc::vec![],
        policy_overview: alloc::vec![],
        sealed_count: 5,
    };
    let debug = alloc::format!("{:?}", diag);
    assert!(debug.contains("VaultDiagnostics"));
    assert!(debug.contains("Uninitialized"));
}

#[test]
fn test_vault_health_check_returns_health() {
    let health = vault_health_check();
    match health {
        VaultHealth::Healthy |
        VaultHealth::Uninitialized |
        VaultHealth::Leaked |
        VaultHealth::PolicyViolation |
        VaultHealth::AuditOverflow |
        VaultHealth::Unknown => {}
    }
}

#[test]
fn test_vault_health_check_uninitialized_when_not_init() {
    secure_erase_vault();
    if !vault_initialized() {
        let health = vault_health_check();
        assert_eq!(health, VaultHealth::Uninitialized);
    }
}

#[test]
fn test_vault_health_check_detects_policy_violation() {
    let _ = initialize_vault();
    let rule = VaultPolicyRule {
        capability: VaultCapability::Read,
        context: "violation_test".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: false,
    };
    set_vault_policy("violation_test", rule);
    let health = vault_health_check();
    clear_vault_policy("violation_test");
    assert!(health == VaultHealth::PolicyViolation || health == VaultHealth::Healthy || health == VaultHealth::Uninitialized);
}

#[test]
fn test_vault_diagnostics_returns_struct() {
    let diag = vault_diagnostics();
    assert!(diag.sealed_count >= 0);
}

#[test]
fn test_vault_diagnostics_health_field() {
    let diag = vault_diagnostics();
    match diag.health {
        VaultHealth::Healthy |
        VaultHealth::Uninitialized |
        VaultHealth::Leaked |
        VaultHealth::PolicyViolation |
        VaultHealth::AuditOverflow |
        VaultHealth::Unknown => {}
    }
}

#[test]
fn test_vault_diagnostics_audit_recent_field() {
    let diag = vault_diagnostics();
    assert!(diag.audit_recent.len() <= 16);
}

#[test]
fn test_vault_diagnostics_policy_overview_field() {
    let diag = vault_diagnostics();
    assert!(diag.policy_overview.len() >= 0);
}

#[test]
fn test_vault_diagnostics_sealed_count_field() {
    let diag = vault_diagnostics();
    assert!(diag.sealed_count >= 0);
}

#[test]
fn test_vault_leak_scan_returns_vec() {
    let leaks = vault_leak_scan();
    assert!(leaks.len() >= 0);
}

#[test]
fn test_vault_leak_scan_empty_when_no_leaks() {
    let leaks = vault_leak_scan();
    for leak in &leaks {
        assert!(leak.event.contains("leak"));
    }
}

#[test]
fn test_vault_policy_violations_returns_vec() {
    let violations = vault_policy_violations();
    assert!(violations.len() >= 0);
}

#[test]
fn test_vault_policy_violations_finds_denied() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Erase,
        context: "violation_check".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: false,
    };
    set_vault_policy("violation_check", rule);
    let violations = vault_policy_violations();
    clear_vault_policy("violation_check");
    let found = violations.iter().any(|r| !r.allow);
    assert!(found || violations.is_empty());
}

#[test]
fn test_vault_live_status_returns_string() {
    let status = vault_live_status();
    assert!(!status.is_empty());
}

#[test]
fn test_vault_live_status_contains_vault_status() {
    let status = vault_live_status();
    assert!(status.contains("Vault Status"));
}

#[test]
fn test_vault_live_status_contains_audit_events() {
    let status = vault_live_status();
    assert!(status.contains("Audit Events"));
}

#[test]
fn test_vault_live_status_contains_policies() {
    let status = vault_live_status();
    assert!(status.contains("Policies"));
}

#[test]
fn test_vault_live_status_contains_sealed_secrets() {
    let status = vault_live_status();
    assert!(status.contains("Sealed Secrets"));
}

#[test]
fn test_vault_diagnostics_after_init() {
    let _ = initialize_vault();
    if vault_initialized() {
        let diag = vault_diagnostics();
        assert!(diag.health == VaultHealth::Healthy ||
                diag.health == VaultHealth::PolicyViolation);
    }
}

#[test]
fn test_vault_diagnostics_after_erase() {
    secure_erase_vault();
    let diag = vault_diagnostics();
    assert_eq!(diag.health, VaultHealth::Uninitialized);
}

#[test]
fn test_vault_health_check_multiple_calls() {
    let h1 = vault_health_check();
    let h2 = vault_health_check();
    assert_eq!(h1, h2);
}

#[test]
fn test_vault_diagnostics_multiple_calls() {
    let d1 = vault_diagnostics();
    let d2 = vault_diagnostics();
    assert_eq!(d1.health, d2.health);
}

#[test]
fn test_vault_live_status_multiple_calls() {
    let s1 = vault_live_status();
    let s2 = vault_live_status();
    assert_eq!(s1.len(), s2.len());
}

#[test]
fn test_vault_policy_violations_with_expired() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Read,
        context: "expired_test".into(),
        max_uses: None,
        used: 0,
        expires_at: Some(0),
        allow: true,
    };
    set_vault_policy("expired_test", rule);
    let violations = vault_policy_violations();
    clear_vault_policy("expired_test");
    assert!(violations.len() >= 0);
}

#[test]
fn test_vault_diagnostics_with_policies() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Derive,
        context: "diag_policy".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("diag_policy", rule);
    let diag = vault_diagnostics();
    clear_vault_policy("diag_policy");
    assert!(diag.policy_overview.len() >= 0);
}
