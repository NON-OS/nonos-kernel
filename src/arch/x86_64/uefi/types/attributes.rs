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

use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VariableAttributes(u32);

impl VariableAttributes {
    pub const NONE: Self = Self(0);
    pub const NON_VOLATILE: Self = Self(0x00000001);
    pub const BOOTSERVICE_ACCESS: Self = Self(0x00000002);
    pub const RUNTIME_ACCESS: Self = Self(0x00000004);
    pub const HARDWARE_ERROR_RECORD: Self = Self(0x00000008);
    pub const AUTHENTICATED_WRITE_ACCESS: Self = Self(0x00000010);
    pub const TIME_BASED_AUTHENTICATED_WRITE_ACCESS: Self = Self(0x00000020);
    pub const APPEND_WRITE: Self = Self(0x00000040);
    pub const ENHANCED_AUTHENTICATED_ACCESS: Self = Self(0x00000080);
    pub const DEFAULT_NV_BS_RT: Self =
        Self(Self::NON_VOLATILE.0 | Self::BOOTSERVICE_ACCESS.0 | Self::RUNTIME_ACCESS.0);

    #[inline]
    pub const fn empty() -> Self { Self(0) }

    #[inline]
    pub const fn bits(&self) -> u32 { self.0 }

    #[inline]
    pub const fn from_bits(bits: u32) -> Self { Self(bits) }

    #[inline]
    pub const fn from_bits_truncate(bits: u32) -> Self { Self(bits & 0xFF) }

    #[inline]
    pub const fn contains(&self, other: Self) -> bool { (self.0 & other.0) == other.0 }

    #[inline]
    pub const fn is_empty(&self) -> bool { self.0 == 0 }

    #[inline]
    pub const fn is_non_volatile(&self) -> bool { self.contains(Self::NON_VOLATILE) }

    #[inline]
    pub const fn is_runtime_access(&self) -> bool { self.contains(Self::RUNTIME_ACCESS) }

    #[inline]
    pub const fn requires_authentication(&self) -> bool {
        self.contains(Self::TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
            || self.contains(Self::ENHANCED_AUTHENTICATED_ACCESS)
    }

    #[inline]
    pub fn insert(&mut self, other: Self) { self.0 |= other.0; }

    #[inline]
    pub fn remove(&mut self, other: Self) { self.0 &= !other.0; }

    #[inline]
    pub fn toggle(&mut self, other: Self) { self.0 ^= other.0; }

    #[inline]
    pub fn set(&mut self, other: Self, value: bool) {
        if value { self.insert(other); } else { self.remove(other); }
    }

    #[inline]
    pub const fn intersection(self, other: Self) -> Self { Self(self.0 & other.0) }

    #[inline]
    pub const fn union(self, other: Self) -> Self { Self(self.0 | other.0) }
}

impl core::ops::BitOr for VariableAttributes {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}

impl core::ops::BitOrAssign for VariableAttributes {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
}

impl core::ops::BitAnd for VariableAttributes {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self { Self(self.0 & rhs.0) }
}

impl core::ops::BitAndAssign for VariableAttributes {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) { self.0 &= rhs.0; }
}

impl core::ops::BitXor for VariableAttributes {
    type Output = Self;
    #[inline]
    fn bitxor(self, rhs: Self) -> Self { Self(self.0 ^ rhs.0) }
}

impl core::ops::Not for VariableAttributes {
    type Output = Self;
    #[inline]
    fn not(self) -> Self { Self(!self.0) }
}

impl fmt::Debug for VariableAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_set();
        if self.contains(Self::NON_VOLATILE) { list.entry(&"NON_VOLATILE"); }
        if self.contains(Self::BOOTSERVICE_ACCESS) { list.entry(&"BOOTSERVICE_ACCESS"); }
        if self.contains(Self::RUNTIME_ACCESS) { list.entry(&"RUNTIME_ACCESS"); }
        if self.contains(Self::HARDWARE_ERROR_RECORD) { list.entry(&"HARDWARE_ERROR_RECORD"); }
        if self.contains(Self::AUTHENTICATED_WRITE_ACCESS) { list.entry(&"AUTHENTICATED_WRITE_ACCESS"); }
        if self.contains(Self::TIME_BASED_AUTHENTICATED_WRITE_ACCESS) { list.entry(&"TIME_BASED_AUTHENTICATED_WRITE_ACCESS"); }
        if self.contains(Self::APPEND_WRITE) { list.entry(&"APPEND_WRITE"); }
        if self.contains(Self::ENHANCED_AUTHENTICATED_ACCESS) { list.entry(&"ENHANCED_AUTHENTICATED_ACCESS"); }
        list.finish()
    }
}

impl Default for VariableAttributes {
    fn default() -> Self { Self::empty() }
}
