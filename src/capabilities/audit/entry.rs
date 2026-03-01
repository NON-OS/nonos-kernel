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

use crate::capabilities::types::Capability;

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp_ms: u64,
    pub owner_module: u64,
    pub action: &'static str,
    pub capability: Option<Capability>,
    pub nonce: u64,
    pub success: bool,
}

impl AuditEntry {
    #[inline]
    pub fn in_time_range(&self, start_ms: u64, end_ms: u64) -> bool {
        self.timestamp_ms >= start_ms && self.timestamp_ms <= end_ms
    }

    #[inline]
    pub fn matches_module(&self, module_id: u64) -> bool {
        self.owner_module == module_id
    }

    #[inline]
    pub fn matches_action(&self, action: &str) -> bool {
        self.action == action
    }

    #[inline]
    pub fn age_ms(&self) -> u64 {
        crate::time::timestamp_millis().saturating_sub(self.timestamp_ms)
    }

    pub fn matches_capability(&self, cap: Capability) -> bool {
        self.capability.map_or(false, |c| c == cap)
    }
}

impl core::fmt::Display for AuditEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let cap_str = match &self.capability {
            Some(c) => alloc::format!("{:?}", c),
            None => alloc::string::String::from("-"),
        };
        let status = if self.success { "OK" } else { "FAIL" };
        write!(
            f,
            "[{}ms] mod:{} {} cap:{} nonce:{:016x} {}",
            self.timestamp_ms, self.owner_module, self.action, cap_str, self.nonce, status
        )
    }
}
