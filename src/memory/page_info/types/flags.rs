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

use super::super::constants::flags;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PageFlags {
    bits: u32,
}

impl PageFlags {
    pub const PRESENT: Self = Self { bits: 1 << flags::PRESENT_BIT };
    pub const WRITABLE: Self = Self { bits: 1 << flags::WRITABLE_BIT };
    pub const USER: Self = Self { bits: 1 << flags::USER_BIT };
    pub const DIRTY: Self = Self { bits: 1 << flags::DIRTY_BIT };
    pub const ACCESSED: Self = Self { bits: 1 << flags::ACCESSED_BIT };
    pub const LOCKED: Self = Self { bits: 1 << flags::LOCKED_BIT };
    pub const ENCRYPTED: Self = Self { bits: 1 << flags::ENCRYPTED_BIT };
    pub const EMPTY: Self = Self { bits: 0 };

    pub const fn from_bits(bits: u32) -> Self {
        Self { bits }
    }
    pub const fn bits(&self) -> u32 {
        self.bits
    }
    pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }
    pub const fn union(self, other: Self) -> Self {
        Self { bits: self.bits | other.bits }
    }
    pub const fn intersection(self, other: Self) -> Self {
        Self { bits: self.bits & other.bits }
    }
    pub const fn difference(self, other: Self) -> Self {
        Self { bits: self.bits & !other.bits }
    }
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }
}
