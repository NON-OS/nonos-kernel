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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityLevel {
    Public,
    Internal,
    Confidential,
    Secret,
    TopSecret,
}

impl SecurityLevel {
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Public => SECURITY_LEVEL_PUBLIC,
            Self::Internal => SECURITY_LEVEL_INTERNAL,
            Self::Confidential => SECURITY_LEVEL_CONFIDENTIAL,
            Self::Secret => SECURITY_LEVEL_SECRET,
            Self::TopSecret => SECURITY_LEVEL_TOP_SECRET,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Internal => "Internal",
            Self::Confidential => "Confidential",
            Self::Secret => "Secret",
            Self::TopSecret => "TopSecret",
        }
    }

    pub const fn requires_encryption(&self) -> bool {
        self.as_u8() >= ENCRYPTION_THRESHOLD_LEVEL
    }

    pub const fn requires_secure_scrub(&self) -> bool {
        matches!(self, Self::Secret | Self::TopSecret)
    }

    pub const fn scrub_passes(&self) -> usize {
        match self {
            Self::TopSecret => SECURE_SCRUB_PASSES,
            Self::Secret => 1,
            _ => 0,
        }
    }
}
