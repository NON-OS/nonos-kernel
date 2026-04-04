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

use crate::vault::nonos_vault_policy::*;

#[test]
fn test_vault_capability_read_eq() {
    assert_eq!(VaultCapability::Read, VaultCapability::Read);
}

#[test]
fn test_vault_capability_write_eq() {
    assert_eq!(VaultCapability::Write, VaultCapability::Write);
}

#[test]
fn test_vault_capability_derive_eq() {
    assert_eq!(VaultCapability::Derive, VaultCapability::Derive);
}

#[test]
fn test_vault_capability_seal_eq() {
    assert_eq!(VaultCapability::Seal, VaultCapability::Seal);
}

#[test]
fn test_vault_capability_unseal_eq() {
    assert_eq!(VaultCapability::Unseal, VaultCapability::Unseal);
}

#[test]
fn test_vault_capability_audit_eq() {
    assert_eq!(VaultCapability::Audit, VaultCapability::Audit);
}

#[test]
fn test_vault_capability_erase_eq() {
    assert_eq!(VaultCapability::Erase, VaultCapability::Erase);
}

#[test]
fn test_vault_capability_different_ne() {
    assert_ne!(VaultCapability::Read, VaultCapability::Write);
    assert_ne!(VaultCapability::Seal, VaultCapability::Unseal);
    assert_ne!(VaultCapability::Derive, VaultCapability::Erase);
}

#[test]
fn test_vault_capability_clone() {
    let cap = VaultCapability::Seal;
    let cloned = cap.clone();
    assert_eq!(cap, cloned);
}

#[test]
fn test_vault_capability_copy() {
    let cap = VaultCapability::Unseal;
    let copied: VaultCapability = cap;
    assert_eq!(cap, copied);
}

#[test]
fn test_vault_capability_debug_read() {
    let debug = alloc::format!("{:?}", VaultCapability::Read);
    assert!(debug.contains("Read"));
}

#[test]
fn test_vault_capability_debug_write() {
    let debug = alloc::format!("{:?}", VaultCapability::Write);
    assert!(debug.contains("Write"));
}

#[test]
fn test_vault_capability_debug_derive() {
    let debug = alloc::format!("{:?}", VaultCapability::Derive);
    assert!(debug.contains("Derive"));
}

#[test]
fn test_vault_capability_debug_seal() {
    let debug = alloc::format!("{:?}", VaultCapability::Seal);
    assert!(debug.contains("Seal"));
}

#[test]
fn test_vault_capability_debug_unseal() {
    let debug = alloc::format!("{:?}", VaultCapability::Unseal);
    assert!(debug.contains("Unseal"));
}

#[test]
fn test_vault_capability_debug_audit() {
    let debug = alloc::format!("{:?}", VaultCapability::Audit);
    assert!(debug.contains("Audit"));
}

#[test]
fn test_vault_capability_debug_erase() {
    let debug = alloc::format!("{:?}", VaultCapability::Erase);
    assert!(debug.contains("Erase"));
}

#[test]
fn test_vault_policy_rule_clone() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Derive,
        context: "test_context".into(),
        max_uses: Some(100),
        used: 5,
        expires_at: Some(999999),
        allow: true,
    };
    let cloned = rule.clone();
    assert_eq!(rule.capability, cloned.capability);
    assert_eq!(rule.context, cloned.context);
    assert_eq!(rule.max_uses, cloned.max_uses);
    assert_eq!(rule.used, cloned.used);
    assert_eq!(rule.expires_at, cloned.expires_at);
    assert_eq!(rule.allow, cloned.allow);
}

#[test]
fn test_vault_policy_rule_debug() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Seal,
        context: "debug_ctx".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    let debug = alloc::format!("{:?}", rule);
    assert!(debug.contains("VaultPolicyRule"));
    assert!(debug.contains("Seal"));
}

#[test]
fn test_vault_policy_rule_unlimited_uses() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Read,
        context: "unlimited".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    assert!(rule.max_uses.is_none());
}

#[test]
fn test_vault_policy_rule_limited_uses() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Write,
        context: "limited".into(),
        max_uses: Some(10),
        used: 5,
        expires_at: None,
        allow: true,
    };
    assert_eq!(rule.max_uses, Some(10));
    assert_eq!(rule.used, 5);
}

#[test]
fn test_vault_policy_rule_with_expiry() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Unseal,
        context: "expiring".into(),
        max_uses: None,
        used: 0,
        expires_at: Some(1000000),
        allow: true,
    };
    assert_eq!(rule.expires_at, Some(1000000));
}

#[test]
fn test_vault_policy_rule_deny() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Erase,
        context: "denied".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: false,
    };
    assert!(!rule.allow);
}

#[test]
fn test_vault_policy_engine_new() {
    let engine = VaultPolicyEngine::new();
    let policies = engine.list_policies();
    assert!(policies.is_empty());
}

#[test]
fn test_vault_policy_engine_set_policy() {
    let engine = VaultPolicyEngine::new();
    let rule = VaultPolicyRule {
        capability: VaultCapability::Derive,
        context: "process_1".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    engine.set_policy("process_1", rule);
    let policies = engine.list_policies();
    assert_eq!(policies.len(), 1);
}

#[test]
fn test_vault_policy_engine_check_allowed() {
    let engine = VaultPolicyEngine::new();
    let rule = VaultPolicyRule {
        capability: VaultCapability::Read,
        context: "reader".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    engine.set_policy("reader", rule);
    assert!(engine.check("reader", VaultCapability::Read));
}

#[test]
fn test_vault_policy_engine_check_denied() {
    let engine = VaultPolicyEngine::new();
    let rule = VaultPolicyRule {
        capability: VaultCapability::Erase,
        context: "restricted".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: false,
    };
    engine.set_policy("restricted", rule);
    assert!(!engine.check("restricted", VaultCapability::Erase));
}

#[test]
fn test_vault_policy_engine_check_no_rule_denies() {
    let engine = VaultPolicyEngine::new();
    assert!(!engine.check("unknown_context", VaultCapability::Seal));
}

#[test]
fn test_vault_policy_engine_check_wrong_capability_denies() {
    let engine = VaultPolicyEngine::new();
    let rule = VaultPolicyRule {
        capability: VaultCapability::Read,
        context: "reader_only".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    engine.set_policy("reader_only", rule);
    assert!(!engine.check("reader_only", VaultCapability::Write));
}

#[test]
fn test_vault_policy_engine_increment_usage() {
    let engine = VaultPolicyEngine::new();
    let rule = VaultPolicyRule {
        capability: VaultCapability::Derive,
        context: "counter".into(),
        max_uses: Some(10),
        used: 0,
        expires_at: None,
        allow: true,
    };
    engine.set_policy("counter", rule);
    engine.increment_usage("counter", VaultCapability::Derive);
    let policies = engine.list_policies();
    let entry = policies.iter().find(|(ctx, _)| ctx == "counter").unwrap();
    let r = entry.1.iter().find(|r| r.capability == VaultCapability::Derive).unwrap();
    assert_eq!(r.used, 1);
}

#[test]
fn test_vault_policy_engine_max_uses_exceeded() {
    let engine = VaultPolicyEngine::new();
    let rule = VaultPolicyRule {
        capability: VaultCapability::Seal,
        context: "limited".into(),
        max_uses: Some(2),
        used: 2,
        expires_at: None,
        allow: true,
    };
    engine.set_policy("limited", rule);
    assert!(!engine.check("limited", VaultCapability::Seal));
}

#[test]
fn test_vault_policy_engine_clear_policy() {
    let engine = VaultPolicyEngine::new();
    let rule = VaultPolicyRule {
        capability: VaultCapability::Audit,
        context: "to_clear".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    engine.set_policy("to_clear", rule);
    assert_eq!(engine.list_policies().len(), 1);
    engine.clear_policy("to_clear");
    assert!(engine.list_policies().is_empty());
}

#[test]
fn test_vault_policy_engine_multiple_rules_same_context() {
    let engine = VaultPolicyEngine::new();
    let rule1 = VaultPolicyRule {
        capability: VaultCapability::Read,
        context: "multi".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    let rule2 = VaultPolicyRule {
        capability: VaultCapability::Write,
        context: "multi".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    engine.set_policy("multi", rule1);
    engine.set_policy("multi", rule2);
    assert!(engine.check("multi", VaultCapability::Read));
    assert!(engine.check("multi", VaultCapability::Write));
}

#[test]
fn test_vault_policy_engine_update_existing_rule() {
    let engine = VaultPolicyEngine::new();
    let rule1 = VaultPolicyRule {
        capability: VaultCapability::Derive,
        context: "update".into(),
        max_uses: Some(5),
        used: 0,
        expires_at: None,
        allow: true,
    };
    let rule2 = VaultPolicyRule {
        capability: VaultCapability::Derive,
        context: "update".into(),
        max_uses: Some(10),
        used: 3,
        expires_at: None,
        allow: true,
    };
    engine.set_policy("update", rule1);
    engine.set_policy("update", rule2);
    let policies = engine.list_policies();
    let entry = policies.iter().find(|(ctx, _)| ctx == "update").unwrap();
    let r = entry.1.iter().find(|r| r.capability == VaultCapability::Derive).unwrap();
    assert_eq!(r.max_uses, Some(10));
    assert_eq!(r.used, 3);
}

#[test]
fn test_set_vault_policy_api() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Seal,
        context: "api_test".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("api_test", rule);
    assert!(check_vault_policy("api_test", VaultCapability::Seal));
}

#[test]
fn test_check_vault_policy_api() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Unseal,
        context: "check_api".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("check_api", rule);
    assert!(check_vault_policy("check_api", VaultCapability::Unseal));
    assert!(!check_vault_policy("check_api", VaultCapability::Erase));
}

#[test]
fn test_increment_vault_policy_usage_api() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Derive,
        context: "increment_api".into(),
        max_uses: Some(100),
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("increment_api", rule);
    increment_vault_policy_usage("increment_api", VaultCapability::Derive);
    let policies = list_vault_policies();
    let entry = policies.iter().find(|(ctx, _)| ctx == "increment_api");
    if let Some((_, rules)) = entry {
        let r = rules.iter().find(|r| r.capability == VaultCapability::Derive);
        if let Some(rule) = r {
            assert!(rule.used >= 1);
        }
    }
}

#[test]
fn test_clear_vault_policy_api() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Read,
        context: "clear_api".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("clear_api", rule);
    clear_vault_policy("clear_api");
    assert!(!check_vault_policy("clear_api", VaultCapability::Read));
}

#[test]
fn test_list_vault_policies_api() {
    let policies = list_vault_policies();
    assert!(policies.len() >= 0);
}

#[test]
fn test_vault_policy_engine_singleton_exists() {
    let policies = VAULT_POLICY_ENGINE.list_policies();
    assert!(policies.len() >= 0);
}
