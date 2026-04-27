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
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct Delegation {
    pub delegator: u64,
    pub delegatee: u64,
    pub capabilities: Vec<Capability>,
    pub expires_at_ms: Option<u64>,
    pub parent_nonce: u64,
    pub signature: [u8; 64],
}

impl Delegation {
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.expires_at_ms.map_or(false, |exp| crate::time::timestamp_millis() >= exp)
    }
    #[inline]
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }
    pub fn remaining_ms(&self) -> Option<u64> {
        self.expires_at_ms.map(|exp| exp.saturating_sub(crate::time::timestamp_millis()))
    }
    #[inline]
    pub fn grants(&self, cap: Capability) -> bool {
        self.capabilities.iter().any(|c| *c == cap)
    }
    #[inline]
    pub fn capability_count(&self) -> usize {
        self.capabilities.len()
    }
    pub fn grants_all(&self, caps: &[Capability]) -> bool {
        caps.iter().all(|c| self.grants(*c))
    }
    pub fn grants_any(&self, caps: &[Capability]) -> bool {
        caps.iter().any(|c| self.grants(*c))
    }
}

impl core::fmt::Display for Delegation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let exp = self
            .expires_at_ms
            .map_or(alloc::string::String::from("never"), |e| alloc::format!("{}ms", e));
        write!(
            f,
            "Delegation[{}->{} caps:{} exp:{}]",
            self.delegator,
            self.delegatee,
            self.capabilities.len(),
            exp
        )
    }
}
