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

use super::super::constants::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionFlags {
    Readable,
    Writable,
    Executable,
    Cacheable,
    Shared,
    Locked,
    Protected,
    Encrypted,
}

impl RegionFlags {
    pub const fn bit(&self) -> u32 {
        match self {
            Self::Readable => FLAG_READABLE,
            Self::Writable => FLAG_WRITABLE,
            Self::Executable => FLAG_EXECUTABLE,
            Self::Cacheable => FLAG_CACHEABLE,
            Self::Shared => FLAG_SHARED,
            Self::Locked => FLAG_LOCKED,
            Self::Protected => FLAG_PROTECTED,
            Self::Encrypted => FLAG_ENCRYPTED,
        }
    }
}
