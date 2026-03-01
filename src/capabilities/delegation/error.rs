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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationError {
    MissingSigningKey,
    InvalidParentToken,
    ParentExpired,
    CapabilityNotHeld,
    DelegationExpired,
    InvalidSignature,
    NoCapabilities,
}

impl DelegationError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MissingSigningKey => "Signing key not available",
            Self::InvalidParentToken => "Parent token is invalid",
            Self::ParentExpired => "Parent token has expired",
            Self::CapabilityNotHeld => "Cannot delegate capability not held",
            Self::DelegationExpired => "Delegation has expired",
            Self::InvalidSignature => "Signature verification failed",
            Self::NoCapabilities => "No capabilities specified",
        }
    }

    pub const fn is_recoverable(&self) -> bool {
        matches!(self, Self::DelegationExpired | Self::ParentExpired)
    }
}

impl core::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
