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
use crate::ipc::nonos_message::{IpcEnvelope, SecurityLevel};
use crate::ipc::nonos_policy::capability::IpcCapability;
use crate::ipc::nonos_policy::module_policy::ModulePolicy;
use crate::ipc::nonos_policy::violation::PolicyViolation;

impl IpcPolicy {
    pub(super) fn check_message_policy(
        &self,
        env: &IpcEnvelope,
        from: &str,
        to: &str,
        policy: &ModulePolicy,
    ) -> bool {
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
        if policy.blocked_destinations.iter().any(|d| d == to) {
            self.record_violation(PolicyViolation::DestinationBlocked {
                from: String::from(from),
                to: String::from(to),
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }
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
        if to.starts_with("kernel") && !policy.has_capability(IpcCapability::KernelAccess) {
            self.record_violation(PolicyViolation::MissingCapability {
                module: String::from(from),
                capability: IpcCapability::KernelAccess,
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.check_security_and_rate(env, from, to, policy)
    }

    fn check_security_and_rate(
        &self,
        env: &IpcEnvelope,
        from: &str,
        _to: &str,
        policy: &ModulePolicy,
    ) -> bool {
        let required = if self.route_requires_encryption(from, _to) {
            SecurityLevel::Encrypted
        } else {
            policy.min_security_level
        };
        if (env.sec_level as u8) < (required as u8) {
            self.record_violation(PolicyViolation::SecurityLevelInsufficient {
                required,
                actual: env.sec_level,
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }
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
        if !self.check_rate_limit(from, policy) {
            self.record_violation(PolicyViolation::RateLimitExceeded {
                module: String::from(from),
                limit: policy.rate_limit_per_sec,
            });
            self.stats.messages_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }
}
