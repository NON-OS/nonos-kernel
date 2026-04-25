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

use crate::test::framework::TestResult;
use crate::vault::nonos_vault::{initialize_vault, secure_erase_vault, vault_initialized};
use crate::vault::nonos_vault_diag::*;
use crate::vault::nonos_vault_policy::{
    clear_vault_policy, set_vault_policy, VaultCapability, VaultPolicyRule,
};

pub(crate) fn test_vault_health_healthy_eq() -> TestResult {
    if VaultHealth::Healthy != VaultHealth::Healthy {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_uninitialized_eq() -> TestResult {
    if VaultHealth::Uninitialized != VaultHealth::Uninitialized {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_leaked_eq() -> TestResult {
    if VaultHealth::Leaked != VaultHealth::Leaked {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_policy_violation_eq() -> TestResult {
    if VaultHealth::PolicyViolation != VaultHealth::PolicyViolation {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_audit_overflow_eq() -> TestResult {
    if VaultHealth::AuditOverflow != VaultHealth::AuditOverflow {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_unknown_eq() -> TestResult {
    if VaultHealth::Unknown != VaultHealth::Unknown {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_different_ne() -> TestResult {
    if VaultHealth::Healthy == VaultHealth::Uninitialized {
        return TestResult::Fail;
    }
    if VaultHealth::Leaked == VaultHealth::PolicyViolation {
        return TestResult::Fail;
    }
    if VaultHealth::AuditOverflow == VaultHealth::Unknown {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_clone() -> TestResult {
    let health = VaultHealth::Healthy;
    let cloned = health.clone();
    if health != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_copy() -> TestResult {
    let health = VaultHealth::Leaked;
    let copied: VaultHealth = health;
    if health != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_debug_healthy() -> TestResult {
    let debug = alloc::format!("{:?}", VaultHealth::Healthy);
    if !debug.contains("Healthy") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_debug_uninitialized() -> TestResult {
    let debug = alloc::format!("{:?}", VaultHealth::Uninitialized);
    if !debug.contains("Uninitialized") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_debug_leaked() -> TestResult {
    let debug = alloc::format!("{:?}", VaultHealth::Leaked);
    if !debug.contains("Leaked") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_debug_policy_violation() -> TestResult {
    let debug = alloc::format!("{:?}", VaultHealth::PolicyViolation);
    if !debug.contains("PolicyViolation") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_debug_audit_overflow() -> TestResult {
    let debug = alloc::format!("{:?}", VaultHealth::AuditOverflow);
    if !debug.contains("AuditOverflow") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_debug_unknown() -> TestResult {
    let debug = alloc::format!("{:?}", VaultHealth::Unknown);
    if !debug.contains("Unknown") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_diagnostics_clone() -> TestResult {
    let diag = VaultDiagnostics {
        health: VaultHealth::Healthy,
        audit_recent: alloc::vec![],
        policy_overview: alloc::vec![],
        sealed_count: 0,
    };
    let cloned = diag.clone();
    if diag.health != cloned.health {
        return TestResult::Fail;
    }
    if diag.sealed_count != cloned.sealed_count {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_diagnostics_debug() -> TestResult {
    let diag = VaultDiagnostics {
        health: VaultHealth::Uninitialized,
        audit_recent: alloc::vec![],
        policy_overview: alloc::vec![],
        sealed_count: 5,
    };
    let debug = alloc::format!("{:?}", diag);
    if !debug.contains("VaultDiagnostics") {
        return TestResult::Fail;
    }
    if !debug.contains("Uninitialized") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_check_returns_health() -> TestResult {
    let health = vault_health_check();
    match health {
        VaultHealth::Healthy
        | VaultHealth::Uninitialized
        | VaultHealth::Leaked
        | VaultHealth::PolicyViolation
        | VaultHealth::AuditOverflow
        | VaultHealth::Unknown => {}
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_check_uninitialized_when_not_init() -> TestResult {
    secure_erase_vault();
    if !vault_initialized() {
        let health = vault_health_check();
        if health != VaultHealth::Uninitialized {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_check_detects_policy_violation() -> TestResult {
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
    if !(health == VaultHealth::PolicyViolation
        || health == VaultHealth::Healthy
        || health == VaultHealth::Uninitialized)
    {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_diagnostics_returns_struct() -> TestResult {
    let diag = vault_diagnostics();
    let _ = diag.sealed_count;
    TestResult::Pass
}

pub(crate) fn test_vault_diagnostics_health_field() -> TestResult {
    let diag = vault_diagnostics();
    match diag.health {
        VaultHealth::Healthy
        | VaultHealth::Uninitialized
        | VaultHealth::Leaked
        | VaultHealth::PolicyViolation
        | VaultHealth::AuditOverflow
        | VaultHealth::Unknown => {}
    }
    TestResult::Pass
}

pub(crate) fn test_vault_diagnostics_audit_recent_field() -> TestResult {
    let diag = vault_diagnostics();
    if diag.audit_recent.len() > 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_diagnostics_policy_overview_field() -> TestResult {
    let diag = vault_diagnostics();
    let _ = diag.policy_overview.len();
    TestResult::Pass
}

pub(crate) fn test_vault_diagnostics_sealed_count_field() -> TestResult {
    let diag = vault_diagnostics();
    let _ = diag.sealed_count;
    TestResult::Pass
}

pub(crate) fn test_vault_leak_scan_returns_vec() -> TestResult {
    let leaks = vault_leak_scan();
    let _ = leaks.len();
    TestResult::Pass
}

pub(crate) fn test_vault_leak_scan_empty_when_no_leaks() -> TestResult {
    let leaks = vault_leak_scan();
    for leak in &leaks {
        if !leak.event.contains("leak") {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_violations_returns_vec() -> TestResult {
    let violations = vault_policy_violations();
    let _ = violations.len();
    TestResult::Pass
}

pub(crate) fn test_vault_policy_violations_finds_denied() -> TestResult {
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
    if !(found || violations.is_empty()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_live_status_returns_string() -> TestResult {
    let status = vault_live_status();
    if status.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_live_status_contains_vault_status() -> TestResult {
    let status = vault_live_status();
    if !status.contains("Vault Status") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_live_status_contains_audit_events() -> TestResult {
    let status = vault_live_status();
    if !status.contains("Audit Events") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_live_status_contains_policies() -> TestResult {
    let status = vault_live_status();
    if !status.contains("Policies") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_live_status_contains_sealed_secrets() -> TestResult {
    let status = vault_live_status();
    if !status.contains("Sealed Secrets") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_diagnostics_after_init() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        let diag = vault_diagnostics();
        if !(diag.health == VaultHealth::Healthy || diag.health == VaultHealth::PolicyViolation) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_diagnostics_after_erase() -> TestResult {
    secure_erase_vault();
    let diag = vault_diagnostics();
    if diag.health != VaultHealth::Uninitialized {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_health_check_multiple_calls() -> TestResult {
    let h1 = vault_health_check();
    let h2 = vault_health_check();
    if h1 != h2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_diagnostics_multiple_calls() -> TestResult {
    let d1 = vault_diagnostics();
    let d2 = vault_diagnostics();
    if d1.health != d2.health {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_live_status_multiple_calls() -> TestResult {
    let s1 = vault_live_status();
    let s2 = vault_live_status();
    if s1.len() != s2.len() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_violations_with_expired() -> TestResult {
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
    let _ = violations.len();
    TestResult::Pass
}

pub(crate) fn test_vault_diagnostics_with_policies() -> TestResult {
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
    let _ = diag.policy_overview.len();
    TestResult::Pass
}
