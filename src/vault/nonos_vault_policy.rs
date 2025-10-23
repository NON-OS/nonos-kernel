//! NØNOS Vault Policy & Access Control 

extern crate alloc;
use alloc::{string::String, vec::Vec, collections::BTreeMap};
use spin::RwLock;
use crate::vault::nonos_vault::{NONOS_VAULT, VaultAuditEvent};

/// Vault capability types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultCapability {
    Read,
    Write,
    Derive,
    Seal,
    Unseal,
    Audit,
    Erase,
}

/// Policy rule
#[derive(Debug, Clone)]
pub struct VaultPolicyRule {
    pub capability: VaultCapability,
    pub context: String,          // e.g. process/user/session id, or "global"
    pub max_uses: Option<u64>,    // None = unlimited
    pub used: u64,                // Usage counter
    pub expires_at: Option<u64>,  // Timestamp expiry
    pub allow: bool,              // Is this allowed?
}

#[derive(Debug)]
pub struct VaultPolicyEngine {
    rules: RwLock<BTreeMap<String, Vec<VaultPolicyRule>>>, // context => rules
}

impl VaultPolicyEngine {
    pub const fn new() -> Self {
        Self {
            rules: RwLock::new(BTreeMap::new()),
        }
    }

    /// Add/update a policy rule for a context
    pub fn set_policy(&self, context: &str, rule: VaultPolicyRule) {
        let mut rules = self.rules.write();
        let entry = rules.entry(context.into()).or_insert_with(Vec::new);
        let capability_debug = format!("{:?}", rule.capability);
        if let Some(existing) = entry.iter_mut().find(|r| r.capability == rule.capability) {
            *existing = rule;
        } else {
            entry.push(rule);
        }
        self.audit("set_policy", Some(context.into()), Some(capability_debug));
    }

    /// Check if a context/capability is allowed
    pub fn check(&self, context: &str, cap: VaultCapability) -> bool {
        let rules = self.rules.read();
        if let Some(list) = rules.get(context) {
            for rule in list {
                if rule.capability == cap {
                    if !rule.allow {
                        self.audit("policy_denied", Some(context.into()), Some(format!("{:?}", cap)));
                        return false;
                    }
                    if let Some(expiry) = rule.expires_at {
                        if crate::time::timestamp_millis() > expiry {
                            self.audit("policy_expired", Some(context.into()), Some(format!("{:?}", cap)));
                            return false;
                        }
                    }
                    if let Some(max) = rule.max_uses {
                        if rule.used >= max {
                            self.audit("policy_limit", Some(context.into()), Some(format!("{:?}", cap)));
                            return false;
                        }
                    }
                    return true;
                }
            }
        }
        // Default: deny if no rule
        self.audit("policy_default_deny", Some(context.into()), Some(format!("{:?}", cap)));
        false
    }

    /// Increment usage counter
    pub fn increment_usage(&self, context: &str, cap: VaultCapability) {
        let mut rules = self.rules.write();
        if let Some(list) = rules.get_mut(context) {
            if let Some(rule) = list.iter_mut().find(|r| r.capability == cap) {
                rule.used += 1;
                self.audit("policy_usage", Some(context.into()), Some(format!("used={}", rule.used)));
            }
        }
    }

    /// Remove all policies
    pub fn clear_policy(&self, context: &str) {
        let mut rules = self.rules.write();
        rules.remove(context);
        self.audit("clear_policy", Some(context.into()), None);
    }

    /// List all policies for diagnostics
    pub fn list_policies(&self) -> Vec<(String, Vec<VaultPolicyRule>)> {
        let rules = self.rules.read();
        rules.iter().map(|(ctx, v)| (ctx.clone(), v.clone())).collect()
    }

    fn audit(&self, event: &str, context: Option<String>, status: Option<String>) {
        let ts = crate::time::timestamp_millis();
        NONOS_VAULT.audit_log().lock().push(VaultAuditEvent {
            timestamp: ts,
            event: event.into(),
            context,
            status,
        });
    }
}

// Global policy engine
pub static VAULT_POLICY_ENGINE: VaultPolicyEngine = VaultPolicyEngine::new();

// ---------- API ----------
pub fn set_vault_policy(context: &str, rule: VaultPolicyRule) {
    VAULT_POLICY_ENGINE.set_policy(context, rule);
}
pub fn check_vault_policy(context: &str, cap: VaultCapability) -> bool {
    VAULT_POLICY_ENGINE.check(context, cap)
}
pub fn increment_vault_policy_usage(context: &str, cap: VaultCapability) {
    VAULT_POLICY_ENGINE.increment_usage(context, cap);
}
pub fn clear_vault_policy(context: &str) {
    VAULT_POLICY_ENGINE.clear_policy(context);
}
pub fn list_vault_policies() -> Vec<(String, Vec<VaultPolicyRule>)> {
    VAULT_POLICY_ENGINE.list_policies()
}
