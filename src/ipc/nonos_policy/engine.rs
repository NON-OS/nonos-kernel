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

//! Main IPC policy engine.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use crate::syscall::capabilities::CapabilityToken;
use crate::ipc::nonos_message::{IpcEnvelope, SecurityLevel};
use super::capability::IpcCapability;
use super::module_policy::ModulePolicy;
use super::violation::PolicyViolation;

/// Maximum violations to keep in audit log
const MAX_VIOLATIONS: usize = 1000;

/// Rate limiting tracker per module
struct RateLimitTracker {
    /// Messages sent in current window
    count: AtomicU64,
    /// Window start timestamp (ms)
    window_start_ms: AtomicU64,
}

impl RateLimitTracker {
    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            window_start_ms: AtomicU64::new(0),
        }
    }

    /// Check and update rate limit. Returns true if allowed.
    fn check_and_increment(&self, limit_per_sec: u32) -> bool {
        if limit_per_sec == 0 {
            return true; // Unlimited
        }

        let now_ms = crate::time::timestamp_millis();
        let window_start = self.window_start_ms.load(Ordering::Relaxed);

        // Reset window every second
        if now_ms.saturating_sub(window_start) >= 1000 {
            self.window_start_ms.store(now_ms, Ordering::Relaxed);
            self.count.store(1, Ordering::Relaxed);
            return true;
        }

        // Check if under limit
        let current = self.count.fetch_add(1, Ordering::Relaxed);
        current < limit_per_sec as u64
    }

    /// Reset the tracker
    fn reset(&self) {
        self.count.store(0, Ordering::Relaxed);
        self.window_start_ms.store(0, Ordering::Relaxed);
    }
}

/// Policy statistics (atomic counters)
struct PolicyStats {
    messages_allowed: AtomicU64,
    messages_denied: AtomicU64,
    channels_created: AtomicU64,
    channels_denied: AtomicU64,
    rate_limit_hits: AtomicU64,
}

impl PolicyStats {
    const fn new() -> Self {
        Self {
            messages_allowed: AtomicU64::new(0),
            messages_denied: AtomicU64::new(0),
            channels_created: AtomicU64::new(0),
            channels_denied: AtomicU64::new(0),
            rate_limit_hits: AtomicU64::new(0),
        }
    }
}

/// Statistics snapshot
#[derive(Debug, Clone, Default)]
pub struct PolicyStatsSnapshot {
    pub messages_allowed: u64,
    pub messages_denied: u64,
    pub channels_created: u64,
    pub channels_denied: u64,
    pub rate_limit_hits: u64,
    pub registered_modules: usize,
    pub recent_violations: usize,
}

/// Main IPC policy engine
pub struct IpcPolicy {
    /// Global maximum message size
    max_message_bytes: usize,
    /// Allow unsigned messages globally
    allow_unsigned: bool,
    /// Per-module policies
    module_policies: RwLock<BTreeMap<String, ModulePolicy>>,
    /// Rate limiters per module
    rate_limiters: RwLock<BTreeMap<String, RateLimitTracker>>,
    /// Recent policy violations for audit
    violations: RwLock<Vec<PolicyViolation>>,
    /// Statistics
    stats: PolicyStats,
    /// Mandatory encryption routes (from -> to)
    encrypted_routes: RwLock<Vec<(String, String)>>,
}

impl IpcPolicy {
    /// Create a new policy engine
    pub const fn new() -> Self {
        Self {
            max_message_bytes: 1 << 20, // 1 MiB global cap
            allow_unsigned: true,
            module_policies: RwLock::new(BTreeMap::new()),
            rate_limiters: RwLock::new(BTreeMap::new()),
            violations: RwLock::new(Vec::new()),
            stats: PolicyStats::new(),
            encrypted_routes: RwLock::new(Vec::new()),
        }
    }

    /// Set global maximum message size
    pub fn set_max_message_size(&mut self, size: usize) {
        self.max_message_bytes = size;
    }

    /// Set whether unsigned messages are allowed globally
    pub fn set_allow_unsigned(&mut self, allow: bool) {
        self.allow_unsigned = allow;
    }

    /// Register a module policy
    pub fn register_module(&self, module: &str, policy: ModulePolicy) {
        self.module_policies
            .write()
            .insert(String::from(module), policy);
    }

    /// Unregister a module
    pub fn unregister_module(&self, module: &str) {
        self.module_policies.write().remove(module);
        self.rate_limiters.write().remove(module);
    }

    /// Get or create default policy for a module
    fn get_module_policy(&self, module: &str) -> ModulePolicy {
        let policies = self.module_policies.read();
        if let Some(policy) = policies.get(module) {
            policy.clone()
        } else {
            // Default policy based on module name patterns
            if module.starts_with("kernel")
                || module == "scheduler"
                || module == "memory"
                || module == "security"
            {
                ModulePolicy::kernel()
            } else if module.starts_with("user_") || module.starts_with("app_") {
                ModulePolicy::user_restricted()
            } else {
                ModulePolicy::default()
            }
        }
    }

    /// Add a mandatory encryption route
    pub fn require_encryption(&self, from: &str, to: &str) {
        self.encrypted_routes
            .write()
            .push((String::from(from), String::from(to)));
    }

    /// Check rate limit for a module
    fn check_rate_limit(&self, module: &str, policy: &ModulePolicy) -> bool {
        if policy.has_capability(IpcCapability::UnlimitedRate) {
            return true;
        }

        let mut limiters = self.rate_limiters.write();
        let limiter = limiters
            .entry(String::from(module))
            .or_insert_with(RateLimitTracker::new);

        let allowed = limiter.check_and_increment(policy.rate_limit_per_sec);
        if !allowed {
            self.stats.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }

    /// Record a policy violation
    fn record_violation(&self, violation: PolicyViolation) {
        let mut violations = self.violations.write();
        if violations.len() >= MAX_VIOLATIONS {
            violations.remove(0);
        }
        violations.push(violation);
    }

    /// Validate capability token
    fn validate_token(&self, token: &CapabilityToken, _module: &str) -> Result<(), &'static str> {
        if !token.is_valid() {
            return Err("token expired or revoked");
        }

        if !token.grants(crate::capabilities::Capability::IPC) {
            return Err("token lacks IPC capability");
        }

        Ok(())
    }

    /// Check if a route requires encryption
    fn route_requires_encryption(&self, from: &str, to: &str) -> bool {
        let routes = self.encrypted_routes.read();
        routes
            .iter()
            .any(|(f, t)| (f == from || f == "*") && (t == to || t == "*"))
    }

    /// Main message authorization check
    #[inline]
    pub fn allow_message(&self, env: &IpcEnvelope, token: &CapabilityToken) -> bool {
        let from = env.from.as_str();
        let to = env.to.as_str();
        let policy = self.get_module_policy(from);

        // 1. Validate token
        if let Err(reason) = self.validate_token(token, from) {
            self.record_violation(PolicyViolation::InvalidToken {
                module: String::from(from),
                reason,
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 2. Check send capability
        if !policy.has_capability(IpcCapability::Send) {
            self.record_violation(PolicyViolation::MissingCapability {
                module: String::from(from),
                capability: IpcCapability::Send,
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 3. Check global message size
        if env.data.len() > self.max_message_bytes {
            self.record_violation(PolicyViolation::MessageTooLarge {
                size: env.data.len(),
                limit: self.max_message_bytes,
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 4. Check module-specific message size
        if env.data.len() > policy.max_message_size
            && !policy.has_capability(IpcCapability::LargeMessages)
        {
            self.record_violation(PolicyViolation::MessageTooLarge {
                size: env.data.len(),
                limit: policy.max_message_size,
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 5. Check blocked destinations
        if policy.blocked_destinations.iter().any(|d| d == to) {
            self.record_violation(PolicyViolation::DestinationBlocked {
                from: String::from(from),
                to: String::from(to),
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 6. Check allowed destinations (if whitelist exists)
        if !policy.allowed_destinations.is_empty()
            && !policy.allowed_destinations.iter().any(|d| d == to)
        {
            self.record_violation(PolicyViolation::DestinationBlocked {
                from: String::from(from),
                to: String::from(to),
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 7. Check kernel access
        if to.starts_with("kernel") && !policy.has_capability(IpcCapability::KernelAccess) {
            self.record_violation(PolicyViolation::MissingCapability {
                module: String::from(from),
                capability: IpcCapability::KernelAccess,
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 8. Check security level
        let required_level = if self.route_requires_encryption(from, to) {
            SecurityLevel::Encrypted
        } else {
            policy.min_security_level
        };

        if (env.sec_level as u8) < (required_level as u8) {
            self.record_violation(PolicyViolation::SecurityLevelInsufficient {
                required: required_level,
                actual: env.sec_level,
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 9. Check unsigned messages
        if env.sec_level == SecurityLevel::None
            && (!self.allow_unsigned || !policy.has_capability(IpcCapability::AllowUnsigned))
        {
            self.record_violation(PolicyViolation::SecurityLevelInsufficient {
                required: SecurityLevel::Signed,
                actual: SecurityLevel::None,
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 10. Check rate limit
        if !self.check_rate_limit(from, &policy) {
            self.record_violation(PolicyViolation::RateLimitExceeded {
                module: String::from(from),
                limit: policy.rate_limit_per_sec,
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        self.stats.messages_allowed.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Check if channel creation is allowed
    #[inline]
    pub fn allow_channel(&self, from: &str, to: &str, token: &CapabilityToken) -> bool {
        let policy = self.get_module_policy(from);

        // Validate token
        if let Err(reason) = self.validate_token(token, from) {
            self.record_violation(PolicyViolation::InvalidToken {
                module: String::from(from),
                reason,
            });
            self.stats.channels_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Check create channel capability
        if !policy.has_capability(IpcCapability::CreateChannel) {
            self.record_violation(PolicyViolation::ChannelCreationDenied {
                from: String::from(from),
                to: String::from(to),
            });
            self.stats.channels_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Check destination restrictions
        if policy.blocked_destinations.iter().any(|d| d == to) {
            self.record_violation(PolicyViolation::ChannelCreationDenied {
                from: String::from(from),
                to: String::from(to),
            });
            self.stats.channels_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Check kernel access for kernel channels
        if to.starts_with("kernel") && !policy.has_capability(IpcCapability::KernelAccess) {
            self.record_violation(PolicyViolation::ChannelCreationDenied {
                from: String::from(from),
                to: String::from(to),
            });
            self.stats.channels_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        self.stats.channels_created.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Get policy statistics
    pub fn get_stats(&self) -> PolicyStatsSnapshot {
        PolicyStatsSnapshot {
            messages_allowed: self.stats.messages_allowed.load(Ordering::Relaxed),
            messages_denied: self.stats.messages_denied.load(Ordering::Relaxed),
            channels_created: self.stats.channels_created.load(Ordering::Relaxed),
            channels_denied: self.stats.channels_denied.load(Ordering::Relaxed),
            rate_limit_hits: self.stats.rate_limit_hits.load(Ordering::Relaxed),
            registered_modules: self.module_policies.read().len(),
            recent_violations: self.violations.read().len(),
        }
    }

    /// Get recent violations for audit
    pub fn get_recent_violations(&self) -> Vec<PolicyViolation> {
        self.violations.read().clone()
    }

    /// Clear violation history
    pub fn clear_violations(&self) {
        self.violations.write().clear();
    }

    /// Reset all rate limiters
    pub fn reset_rate_limiters(&self) {
        for limiter in self.rate_limiters.read().values() {
            limiter.reset();
        }
    }
}

impl Default for IpcPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Global policy instance
static POLICY_INSTANCE: IpcPolicy = IpcPolicy::new();

/// Get the global policy engine
#[inline]
pub fn get_policy() -> &'static IpcPolicy {
    &POLICY_INSTANCE
}

/// Legacy compatibility: reference to active policy
/// Prefer using `get_policy()` for new code
pub static ACTIVE_POLICY: &IpcPolicy = &POLICY_INSTANCE;

/// Initialize IPC policy with default module configurations
pub fn init_default_policies() {
    let policy = get_policy();

    // Kernel modules get full access
    policy.register_module("kernel", ModulePolicy::kernel());
    policy.register_module("scheduler", ModulePolicy::kernel());
    policy.register_module("memory", ModulePolicy::kernel());
    policy.register_module("security", ModulePolicy::kernel());
    policy.register_module("crypto", ModulePolicy::kernel());
    policy.register_module("filesystem", ModulePolicy::kernel());
    policy.register_module("network", ModulePolicy::kernel());
    policy.register_module("capability_validator", ModulePolicy::kernel());

    // Require encryption for sensitive routes
    policy.require_encryption("*", "security");
    policy.require_encryption("*", "crypto");
    policy.require_encryption("*", "vault");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_tracker() {
        let tracker = RateLimitTracker::new();

        // First call should always succeed
        assert!(tracker.check_and_increment(10));

        // Calls within limit should succeed
        for _ in 0..8 {
            assert!(tracker.check_and_increment(10));
        }

        // 10th call should fail (already at 9)
        assert!(!tracker.check_and_increment(10));

        // Reset should allow new calls
        tracker.reset();
        assert!(tracker.check_and_increment(10));
    }

    #[test]
    fn test_unlimited_rate() {
        let tracker = RateLimitTracker::new();

        // Unlimited (0) should always succeed
        for _ in 0..1000 {
            assert!(tracker.check_and_increment(0));
        }
    }
}
