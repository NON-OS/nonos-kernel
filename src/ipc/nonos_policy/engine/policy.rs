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
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::RwLock;

use super::types::{PolicyStats, RateLimitTracker};
use crate::ipc::nonos_policy::module_policy::ModulePolicy;
use crate::ipc::nonos_policy::violation::PolicyViolation;

pub struct IpcPolicy {
    pub(super) max_message_bytes: usize,
    pub(super) allow_unsigned: bool,
    pub(super) module_policies: RwLock<BTreeMap<String, ModulePolicy>>,
    pub(super) rate_limiters: RwLock<BTreeMap<String, RateLimitTracker>>,
    pub(super) violations: RwLock<Vec<PolicyViolation>>,
    pub(super) stats: PolicyStats,
    pub(super) encrypted_routes: RwLock<Vec<(String, String)>>,
}

impl IpcPolicy {
    pub const fn new() -> Self {
        Self {
            max_message_bytes: 1 << 20,
            allow_unsigned: true,
            module_policies: RwLock::new(BTreeMap::new()),
            rate_limiters: RwLock::new(BTreeMap::new()),
            violations: RwLock::new(Vec::new()),
            stats: PolicyStats::new(),
            encrypted_routes: RwLock::new(Vec::new()),
        }
    }

    pub fn set_max_message_size(&mut self, size: usize) {
        self.max_message_bytes = size;
    }

    pub fn set_allow_unsigned(&mut self, allow: bool) {
        self.allow_unsigned = allow;
    }

    pub fn register_module(&self, module: &str, policy: ModulePolicy) {
        self.module_policies.write().insert(String::from(module), policy);
    }

    pub fn unregister_module(&self, module: &str) {
        self.module_policies.write().remove(module);
        self.rate_limiters.write().remove(module);
    }

    pub fn require_encryption(&self, from: &str, to: &str) {
        self.encrypted_routes.write().push((String::from(from), String::from(to)));
    }
}

impl Default for IpcPolicy {
    fn default() -> Self {
        Self::new()
    }
}
