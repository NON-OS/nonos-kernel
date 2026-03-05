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

//! Module-specific policy configuration.

extern crate alloc;

use alloc::{string::String, vec::Vec};

use crate::ipc::nonos_message::SecurityLevel;
use super::capability::IpcCapability;

/// Module-specific policy configuration
#[derive(Debug, Clone)]
pub struct ModulePolicy {
    /// Allowed destination modules (empty = all allowed)
    pub allowed_destinations: Vec<String>,
    /// Blocked destination modules
    pub blocked_destinations: Vec<String>,
    /// Required minimum security level for outgoing messages
    pub min_security_level: SecurityLevel,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Rate limit: messages per second (0 = unlimited)
    pub rate_limit_per_sec: u32,
    /// Capability bitmask
    pub capabilities: u64,
}

impl Default for ModulePolicy {
    fn default() -> Self {
        Self {
            allowed_destinations: Vec::new(),
            blocked_destinations: Vec::new(),
            min_security_level: SecurityLevel::None,
            max_message_size: 64 * 1024, // 64 KB default
            rate_limit_per_sec: 1000,    // 1000 msgs/sec default
            capabilities: IpcCapability::Send as u64
                | IpcCapability::Receive as u64
                | IpcCapability::AllowUnsigned as u64,
        }
    }
}

impl ModulePolicy {
    /// Create a kernel module policy with full access
    pub fn kernel() -> Self {
        Self {
            allowed_destinations: Vec::new(),
            blocked_destinations: Vec::new(),
            min_security_level: SecurityLevel::None,
            max_message_size: 16 * 1024 * 1024, // 16 MB
            rate_limit_per_sec: 0,               // Unlimited
            capabilities: u64::MAX,              // All capabilities
        }
    }

    /// Create a restricted user module policy
    pub fn user_restricted() -> Self {
        Self {
            allowed_destinations: Vec::new(),
            blocked_destinations: alloc::vec![
                String::from("kernel"),
                String::from("security"),
                String::from("crypto_core"),
            ],
            min_security_level: SecurityLevel::Signed,
            max_message_size: 16 * 1024, // 16 KB
            rate_limit_per_sec: 100,
            capabilities: IpcCapability::Send as u64 | IpcCapability::Receive as u64,
        }
    }

    /// Check if module has a specific capability
    #[inline]
    pub fn has_capability(&self, cap: IpcCapability) -> bool {
        self.capabilities & (cap as u64) != 0
    }

    /// Add a capability
    pub fn with_capability(mut self, cap: IpcCapability) -> Self {
        self.capabilities |= cap as u64;
        self
    }

    /// Remove a capability
    pub fn without_capability(mut self, cap: IpcCapability) -> Self {
        self.capabilities &= !(cap as u64);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_policy_default() {
        let policy = ModulePolicy::default();
        assert!(policy.has_capability(IpcCapability::Send));
        assert!(policy.has_capability(IpcCapability::Receive));
        assert!(policy.has_capability(IpcCapability::AllowUnsigned));
        assert!(!policy.has_capability(IpcCapability::KernelAccess));
    }

    #[test]
    fn test_module_policy_kernel() {
        let policy = ModulePolicy::kernel();
        assert!(policy.has_capability(IpcCapability::Send));
        assert!(policy.has_capability(IpcCapability::KernelAccess));
        assert!(policy.has_capability(IpcCapability::UnlimitedRate));
        assert_eq!(policy.rate_limit_per_sec, 0);
    }

    #[test]
    fn test_module_policy_user_restricted() {
        let policy = ModulePolicy::user_restricted();
        assert!(policy.has_capability(IpcCapability::Send));
        assert!(!policy.has_capability(IpcCapability::KernelAccess));
        assert!(!policy.has_capability(IpcCapability::AllowUnsigned));
        assert!(policy.blocked_destinations.contains(&String::from("kernel")));
    }

    #[test]
    fn test_capability_builder() {
        let policy = ModulePolicy::default()
            .with_capability(IpcCapability::KernelAccess)
            .without_capability(IpcCapability::AllowUnsigned);

        assert!(policy.has_capability(IpcCapability::KernelAccess));
        assert!(!policy.has_capability(IpcCapability::AllowUnsigned));
    }
}
