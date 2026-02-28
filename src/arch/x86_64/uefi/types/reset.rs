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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ResetType {
    Cold = 0,
    Warm = 1,
    Shutdown = 2,
    PlatformSpecific = 3,
}

impl ResetType {
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Cold),
            1 => Some(Self::Warm),
            2 => Some(Self::Shutdown),
            3 => Some(Self::PlatformSpecific),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_u32(self) -> u32 { self as u32 }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Cold => "Cold",
            Self::Warm => "Warm",
            Self::Shutdown => "Shutdown",
            Self::PlatformSpecific => "PlatformSpecific",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Cold => "Full power cycle reset",
            Self::Warm => "CPU reset without power cycle",
            Self::Shutdown => "System power off",
            Self::PlatformSpecific => "Platform-specific reset",
        }
    }
}

impl Default for ResetType {
    fn default() -> Self { Self::Cold }
}

impl fmt::Display for ResetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
