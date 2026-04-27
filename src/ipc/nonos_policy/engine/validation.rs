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
use alloc::string::String;
use core::sync::atomic::Ordering;

use super::policy::IpcPolicy;
use super::types::{RateLimitTracker, MAX_VIOLATIONS};
use crate::ipc::nonos_policy::capability::IpcCapability;
use crate::ipc::nonos_policy::module_policy::ModulePolicy;
use crate::ipc::nonos_policy::violation::PolicyViolation;
use crate::syscall::capabilities::CapabilityToken;

impl IpcPolicy {
    pub(super) fn get_module_policy(&self, module: &str) -> ModulePolicy {
        let policies = self.module_policies.read();
        if let Some(policy) = policies.get(module) {
            return policy.clone();
        }
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

    pub(super) fn check_rate_limit(&self, module: &str, policy: &ModulePolicy) -> bool {
        if policy.has_capability(IpcCapability::UnlimitedRate) {
            return true;
        }
        let mut limiters = self.rate_limiters.write();
        let limiter = limiters.entry(String::from(module)).or_insert_with(RateLimitTracker::new);
        let allowed = limiter.check_and_increment(policy.rate_limit_per_sec);
        if !allowed {
            self.stats.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }

    pub(super) fn record_violation(&self, violation: PolicyViolation) {
        let mut violations = self.violations.write();
        if violations.len() >= MAX_VIOLATIONS {
            violations.remove(0);
        }
        violations.push(violation);
    }

    pub(super) fn validate_token(
        &self,
        token: &CapabilityToken,
        _module: &str,
    ) -> Result<(), &'static str> {
        if !token.is_valid() {
            return Err("token expired or revoked");
        }
        if !token.grants(crate::capabilities::Capability::IPC) {
            return Err("token lacks IPC capability");
        }
        Ok(())
    }

    pub(super) fn route_requires_encryption(&self, from: &str, to: &str) -> bool {
        let routes = self.encrypted_routes.read();
        routes.iter().any(|(f, t)| (f == from || f == "*") && (t == to || t == "*"))
    }
}
