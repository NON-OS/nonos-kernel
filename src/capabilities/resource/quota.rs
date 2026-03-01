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

#[derive(Debug, Clone, Copy)]
pub struct ResourceQuota {
    pub bytes: u64,
    pub ops: u64,
    pub expires_at_ms: Option<u64>,
}

impl ResourceQuota {
    pub const fn new(bytes: u64, ops: u64, expires_at_ms: Option<u64>) -> Self {
        Self {
            bytes,
            ops,
            expires_at_ms,
        }
    }

    pub const fn unlimited() -> Self {
        Self {
            bytes: u64::MAX,
            ops: u64::MAX,
            expires_at_ms: None,
        }
    }

    pub const fn bytes_only(bytes: u64) -> Self {
        Self {
            bytes,
            ops: u64::MAX,
            expires_at_ms: None,
        }
    }

    pub const fn ops_only(ops: u64) -> Self {
        Self {
            bytes: u64::MAX,
            ops,
            expires_at_ms: None,
        }
    }

    #[inline]
    pub fn is_expired(&self) -> bool {
        match self.expires_at_ms {
            Some(exp) => crate::time::timestamp_millis() >= exp,
            None => false,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes == 0 && self.ops == 0
    }

    #[inline]
    pub fn is_unlimited(&self) -> bool {
        self.bytes == u64::MAX && self.ops == u64::MAX && self.expires_at_ms.is_none()
    }

    pub fn remaining_ms(&self) -> Option<u64> {
        self.expires_at_ms
            .map(|exp| exp.saturating_sub(crate::time::timestamp_millis()))
    }
}

impl core::fmt::Display for ResourceQuota {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Quota[{}B {}ops", self.bytes, self.ops)?;
        if let Some(exp) = self.expires_at_ms {
            write!(f, " exp:{}ms", exp)?;
        }
        write!(f, "]")
    }
}

impl Default for ResourceQuota {
    fn default() -> Self {
        Self::new(0, 0, None)
    }
}
