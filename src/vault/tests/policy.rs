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
use crate::vault::nonos_vault_policy::*;

pub(crate) fn test_vault_capability_read_eq() -> TestResult {
    if VaultCapability::Read != VaultCapability::Read {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_write_eq() -> TestResult {
    if VaultCapability::Write != VaultCapability::Write {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_derive_eq() -> TestResult {
    if VaultCapability::Derive != VaultCapability::Derive {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_seal_eq() -> TestResult {
    if VaultCapability::Seal != VaultCapability::Seal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_unseal_eq() -> TestResult {
    if VaultCapability::Unseal != VaultCapability::Unseal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_audit_eq() -> TestResult {
    if VaultCapability::Audit != VaultCapability::Audit {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_erase_eq() -> TestResult {
    if VaultCapability::Erase != VaultCapability::Erase {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_different_ne() -> TestResult {
    if VaultCapability::Read == VaultCapability::Write {
        return TestResult::Fail;
    }
    if VaultCapability::Seal == VaultCapability::Unseal {
        return TestResult::Fail;
    }
    if VaultCapability::Derive == VaultCapability::Erase {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_clone() -> TestResult {
    let cap = VaultCapability::Seal;
    let cloned = cap.clone();
    if cap != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_copy() -> TestResult {
    let cap = VaultCapability::Unseal;
    let copied: VaultCapability = cap;
    if cap != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_debug_read() -> TestResult {
    let debug = alloc::format!("{:?}", VaultCapability::Read);
    if !debug.contains("Read") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_debug_write() -> TestResult {
    let debug = alloc::format!("{:?}", VaultCapability::Write);
    if !debug.contains("Write") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_debug_derive() -> TestResult {
    let debug = alloc::format!("{:?}", VaultCapability::Derive);
    if !debug.contains("Derive") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_debug_seal() -> TestResult {
    let debug = alloc::format!("{:?}", VaultCapability::Seal);
    if !debug.contains("Seal") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_debug_unseal() -> TestResult {
    let debug = alloc::format!("{:?}", VaultCapability::Unseal);
    if !debug.contains("Unseal") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_debug_audit() -> TestResult {
    let debug = alloc::format!("{:?}", VaultCapability::Audit);
    if !debug.contains("Audit") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_capability_debug_erase() -> TestResult {
    let debug = alloc::format!("{:?}", VaultCapability::Erase);
    if !debug.contains("Erase") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_rule_clone() -> TestResult {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Derive,
        context: "test_context".into(),
        max_uses: Some(100),
        used: 5,
        expires_at: Some(999999),
        allow: true,
    };
    let cloned = rule.clone();
    if rule.capability != cloned.capability {
        return TestResult::Fail;
    }
    if rule.context != cloned.context {
        return TestResult::Fail;
    }
    if rule.max_uses != cloned.max_uses {
        return TestResult::Fail;
    }
    if rule.used != cloned.used {
        return TestResult::Fail;
    }
    if rule.expires_at != cloned.expires_at {
        return TestResult::Fail;
    }
    if rule.allow != cloned.allow {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_rule_debug() -> TestResult {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Seal,
        context: "debug_ctx".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    let debug = alloc::format!("{:?}", rule);
    if !debug.contains("VaultPolicyRule") {
        return TestResult::Fail;
    }
    if !debug.contains("Seal") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_rule_unlimited_uses() -> TestResult {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Read,
        context: "unlimited".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    if !rule.max_uses.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_rule_limited_uses() -> TestResult {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Write,
        context: "limited".into(),
        max_uses: Some(10),
        used: 5,
        expires_at: None,
        allow: true,
    };
    if rule.max_uses != Some(10) {
        return TestResult::Fail;
    }
    if rule.used != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_rule_with_expiry() -> TestResult {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Unseal,
        context: "expiring".into(),
        max_uses: None,
        used: 0,
        expires_at: Some(1000000),
        allow: true,
    };
    if rule.expires_at != Some(1000000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_rule_deny() -> TestResult {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Erase,
        context: "denied".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: false,
    };
    if rule.allow {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_engine_new() -> TestResult {
    let engine = VaultPolicyEngine::new();
    let policies = engine.list_policies();
    if !policies.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_engine_set_policy() -> TestResult {
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
    if policies.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_engine_check_allowed() -> TestResult {
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
    if !engine.check("reader", VaultCapability::Read) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_engine_check_denied() -> TestResult {
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
    if engine.check("restricted", VaultCapability::Erase) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_engine_check_no_rule_denies() -> TestResult {
    let engine = VaultPolicyEngine::new();
    if engine.check("unknown_context", VaultCapability::Seal) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_engine_check_wrong_capability_denies() -> TestResult {
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
    if engine.check("reader_only", VaultCapability::Write) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_engine_increment_usage() -> TestResult {
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
    if r.used != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_engine_max_uses_exceeded() -> TestResult {
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
    if engine.check("limited", VaultCapability::Seal) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_engine_clear_policy() -> TestResult {
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
    if engine.list_policies().len() != 1 {
        return TestResult::Fail;
    }
    engine.clear_policy("to_clear");
    if !engine.list_policies().is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_engine_multiple_rules_same_context() -> TestResult {
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
    if !engine.check("multi", VaultCapability::Read) {
        return TestResult::Fail;
    }
    if !engine.check("multi", VaultCapability::Write) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_policy_engine_update_existing_rule() -> TestResult {
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
    if r.max_uses != Some(10) {
        return TestResult::Fail;
    }
    if r.used != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_vault_policy_api() -> TestResult {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Seal,
        context: "api_test".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("api_test", rule);
    if !check_vault_policy("api_test", VaultCapability::Seal) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_check_vault_policy_api() -> TestResult {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Unseal,
        context: "check_api".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("check_api", rule);
    if !check_vault_policy("check_api", VaultCapability::Unseal) {
        return TestResult::Fail;
    }
    if check_vault_policy("check_api", VaultCapability::Erase) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_increment_vault_policy_usage_api() -> TestResult {
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
            if rule.used < 1 {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_clear_vault_policy_api() -> TestResult {
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
    if check_vault_policy("clear_api", VaultCapability::Read) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_vault_policies_api() -> TestResult {
    let policies = list_vault_policies();
    let _ = policies.len();
    TestResult::Pass
}

pub(crate) fn test_vault_policy_engine_singleton_exists() -> TestResult {
    let policies = VAULT_POLICY_ENGINE.list_policies();
    let _ = policies.len();
    TestResult::Pass
}
