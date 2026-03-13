// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPolicy {
    Maximum,
    Standard,
    Relaxed,
    Custom,
}

impl SecurityPolicy {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Maximum => "MAXIMUM",
            Self::Standard => "STANDARD",
            Self::Relaxed => "RELAXED",
            Self::Custom => "CUSTOM",
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Maximum),
            1 => Some(Self::Standard),
            2 => Some(Self::Relaxed),
            3 => Some(Self::Custom),
            _ => None,
        }
    }

    pub const fn to_u8(&self) -> u8 {
        match self {
            Self::Maximum => 0,
            Self::Standard => 1,
            Self::Relaxed => 2,
            Self::Custom => 3,
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::Standard
    }
}
