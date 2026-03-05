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

//! Application identifier.

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_APP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AppId(u64);

impl AppId {
    pub const SYSTEM: Self = Self(0);

    pub fn new() -> Self {
        Self(NEXT_APP_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub const fn from_raw(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub fn is_system(self) -> bool {
        self.0 == 0
    }
}

impl Default for AppId {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Display for AppId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "app:{}", self.0)
    }
}
