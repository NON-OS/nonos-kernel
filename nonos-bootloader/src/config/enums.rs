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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationLevel {
    Strict,
    Standard,
    Relaxed,
}

impl VerificationLevel {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "STRICT",
            Self::Standard => "STANDARD",
            Self::Relaxed => "RELAXED",
        }
    }
}

impl Default for VerificationLevel {
    fn default() -> Self {
        Self::Standard
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferredBootMethod {
    Local,
    Network,
    Intelligent,
}

impl PreferredBootMethod {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "LOCAL PREFERRED",
            Self::Network => "NETWORK PREFERRED",
            Self::Intelligent => "INTELLIGENT SELECTION",
        }
    }
}

impl Default for PreferredBootMethod {
    fn default() -> Self {
        Self::Intelligent
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphicsMode {
    Auto,
    HighRes,
    Safe,
    Text,
}

impl GraphicsMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "AUTO",
            Self::HighRes => "HIGH_RES",
            Self::Safe => "SAFE",
            Self::Text => "TEXT",
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Auto),
            1 => Some(Self::HighRes),
            2 => Some(Self::Safe),
            3 => Some(Self::Text),
            _ => None,
        }
    }

    pub const fn to_u8(&self) -> u8 {
        match self {
            Self::Auto => 0,
            Self::HighRes => 1,
            Self::Safe => 2,
            Self::Text => 3,
        }
    }
}

impl Default for GraphicsMode {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryManagementMode {
    Efficient,
    Secure,
    Legacy,
}

impl MemoryManagementMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Efficient => "EFFICIENT",
            Self::Secure => "SECURE",
            Self::Legacy => "LEGACY",
        }
    }
}

impl Default for MemoryManagementMode {
    fn default() -> Self {
        Self::Secure
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackBehavior {
    Halt,
    Retry,
    Continue,
    Reset,
}

impl FallbackBehavior {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Halt => "HALT",
            Self::Retry => "RETRY",
            Self::Continue => "CONTINUE",
            Self::Reset => "RESET",
        }
    }
}

impl Default for FallbackBehavior {
    fn default() -> Self {
        Self::Continue
    }
}
