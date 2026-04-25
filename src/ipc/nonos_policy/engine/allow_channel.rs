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
use crate::ipc::nonos_policy::capability::IpcCapability;
use crate::ipc::nonos_policy::violation::PolicyViolation;
use crate::syscall::capabilities::CapabilityToken;

impl IpcPolicy {
    #[inline]
    pub fn allow_channel(&self, from: &str, to: &str, token: &CapabilityToken) -> bool {
        let policy = self.get_module_policy(from);
        if let Err(reason) = self.validate_token(token, from) {
            self.record_violation(PolicyViolation::InvalidToken {
                module: String::from(from),
                reason,
            });
            self.stats.channels_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if !policy.has_capability(IpcCapability::CreateChannel) {
            self.record_violation(PolicyViolation::ChannelCreationDenied {
                from: String::from(from),
                to: String::from(to),
            });
            self.stats.channels_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if policy.blocked_destinations.iter().any(|d| d == to) {
            self.record_violation(PolicyViolation::ChannelCreationDenied {
                from: String::from(from),
                to: String::from(to),
            });
            self.stats.channels_denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }
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
}
