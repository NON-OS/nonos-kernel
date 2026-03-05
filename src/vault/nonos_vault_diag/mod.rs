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

//! NONOS Vault Diagnostics & Monitoring

extern crate alloc;
use alloc::{string::String, vec::Vec};
use crate::vault::nonos_vault::*;
use crate::vault::nonos_vault_policy::*;
use crate::vault::nonos_vault_audit::*;
use crate::vault::nonos_vault_seal::*;

/// Vault health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultHealth {
    Healthy,
    Uninitialized,
    Leaked,
    PolicyViolation,
    AuditOverflow,
    Unknown,
}

/// Vault diagnostics result
#[derive(Debug, Clone)]
pub struct VaultDiagnostics {
    pub health: VaultHealth,
    pub audit_recent: Vec<VaultAuditEvent>,
    pub policy_overview: Vec<(String, Vec<VaultPolicyRule>)>,
    pub sealed_count: usize,
}

pub fn vault_health_check() -> VaultHealth {
    if !vault_initialized() {
        return VaultHealth::Uninitialized;
    }
    // Check for policy violations
    let policies = list_vault_policies();
    for (_, rules) in &policies {
        for rule in rules {
            if !rule.allow {
                return VaultHealth::PolicyViolation;
            }
        }
    }
    // Check for leaks
    let leaks = vault_audit_filter(Some("leak"), None, None);
    if !leaks.is_empty() {
        return VaultHealth::Leaked;
    }
    // Audit overflow (arbitrary: >10_000 events)
    if vault_audit_export().len() > 10_000 {
        return VaultHealth::AuditOverflow;
    }
    VaultHealth::Healthy
}

/// Diagnostics snapshot
pub fn vault_diagnostics() -> VaultDiagnostics {
    VaultDiagnostics {
        health: vault_health_check(),
        audit_recent: vault_audit_recent(16),
        policy_overview: list_vault_policies(),
        sealed_count: list_sealed().len(),
    }
}

/// Leak detector
pub fn vault_leak_scan() -> Vec<VaultAuditEvent> {
    vault_audit_filter(Some("leak"), None, None)
}

/// Policy introspection: Show all denied or expired policies
pub fn vault_policy_violations() -> Vec<VaultPolicyRule> {
    let mut violations = Vec::new();
    for (_, rules) in list_vault_policies() {
        for rule in rules {
            if !rule.allow || rule.expires_at.map_or(false, |exp| crate::time::timestamp_millis() > exp) {
                violations.push(rule);
            }
        }
    }
    violations
}

/// Live status summary (for CLI or monitoring)
pub fn vault_live_status() -> String {
    let diag = vault_diagnostics();
    format!(
        "Vault Status: {:?}\nAudit Events: {}\nPolicies: {}\nSealed Secrets: {}",
        diag.health,
        diag.audit_recent.len(),
        diag.policy_overview.len(),
        diag.sealed_count
    )
}
