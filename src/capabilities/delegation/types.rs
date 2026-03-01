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

use crate::capabilities::types::Capability;

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
        match self.expires_at_ms {
            Some(exp) => crate::time::timestamp_millis() >= exp,
            None => false,
        }
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    pub fn remaining_ms(&self) -> Option<u64> {
        self.expires_at_ms.map(|exp| {
            let now = crate::time::timestamp_millis();
            exp.saturating_sub(now)
        })
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
        write!(
            f,
            "Delegation[{}->{} caps:{} exp:{}]",
            self.delegator,
            self.delegatee,
            self.capabilities.len(),
            match self.expires_at_ms {
                Some(exp) => alloc::format!("{}ms", exp),
                None => alloc::string::String::from("never"),
            }
        )
    }
}
