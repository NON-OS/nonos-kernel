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
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::policy::IpcPolicy;
use super::types::PolicyStatsSnapshot;
use crate::ipc::nonos_policy::violation::PolicyViolation;

impl IpcPolicy {
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

    pub fn get_recent_violations(&self) -> Vec<PolicyViolation> {
        self.violations.read().clone()
    }

    pub fn clear_violations(&self) {
        self.violations.write().clear();
    }

    pub fn reset_rate_limiters(&self) {
        for limiter in self.rate_limiters.read().values() {
            limiter.reset();
        }
    }
}
