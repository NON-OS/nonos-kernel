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
pub struct CapabilityToken {
    pub owner_module: u64,
    pub permissions: Vec<Capability>,
    pub expires_at_ms: Option<u64>,
    pub nonce: u64,
    pub signature: [u8; 64],
}

impl CapabilityToken {
    /// Creates an empty token with no permissions.
    /// Used as a fallback when no process context is available.
    pub fn empty() -> Self {
        Self {
            owner_module: 0,
            permissions: Vec::new(),
            expires_at_ms: Some(0),
            nonce: 0,
            signature: [0u8; 64],
        }
    }

    #[inline]
    pub fn grants(&self, cap: Capability) -> bool {
        self.permissions.iter().any(|c| *c == cap)
    }

    #[inline]
    pub fn not_expired(&self) -> bool {
        match self.expires_at_ms {
            Some(exp) => crate::time::timestamp_millis() < exp,
            None => true,
        }
    }

    pub fn remaining_ms(&self) -> Option<u64> {
        self.expires_at_ms
            .map(|exp| exp.saturating_sub(crate::time::timestamp_millis()))
    }

    pub fn permission_count(&self) -> usize {
        self.permissions.len()
    }

    pub fn has_any_permission(&self) -> bool {
        !self.permissions.is_empty()
    }

    pub fn grants_all(&self, caps: &[Capability]) -> bool {
        caps.iter().all(|c| self.grants(*c))
    }

    pub fn grants_any(&self, caps: &[Capability]) -> bool {
        caps.iter().any(|c| self.grants(*c))
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.not_expired() && self.has_any_permission()
    }
}

impl core::fmt::Display for CapabilityToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Token[owner:{} caps:{} nonce:{:016x}]",
            self.owner_module,
            self.permissions.len(),
            self.nonce
        )
    }
}
