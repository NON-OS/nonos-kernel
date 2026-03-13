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
pub enum NetworkPolicy {
    Disabled,
    Secured,
    Standard,
    Unrestricted,
}

impl NetworkPolicy {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "DISABLED",
            Self::Secured => "SECURED",
            Self::Standard => "STANDARD",
            Self::Unrestricted => "UNRESTRICTED",
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Disabled),
            1 => Some(Self::Secured),
            2 => Some(Self::Standard),
            3 => Some(Self::Unrestricted),
            _ => None,
        }
    }

    pub const fn to_u8(&self) -> u8 {
        match self {
            Self::Disabled => 0,
            Self::Secured => 1,
            Self::Standard => 2,
            Self::Unrestricted => 3,
        }
    }
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self::Standard
    }
}
