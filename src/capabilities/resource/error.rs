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
pub enum ResourceError {
    MissingSigningKey,
    TokenExpired,
    InvalidSignature,
    InsufficientBytes { requested: u64, available: u64 },
    InsufficientOps { requested: u64, available: u64 },
    ZeroQuota,
}

impl ResourceError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MissingSigningKey => "Signing key not available",
            Self::TokenExpired => "Token has expired",
            Self::InvalidSignature => "Signature verification failed",
            Self::InsufficientBytes { .. } => "Insufficient bytes",
            Self::InsufficientOps { .. } => "Insufficient operations",
            Self::ZeroQuota => "Zero quota not allowed",
        }
    }

    pub const fn is_quota_error(&self) -> bool {
        matches!(
            self,
            Self::InsufficientBytes { .. } | Self::InsufficientOps { .. }
        )
    }
}

impl core::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingSigningKey => write!(f, "Signing key not available"),
            Self::TokenExpired => write!(f, "Token has expired"),
            Self::InvalidSignature => write!(f, "Signature verification failed"),
            Self::InsufficientBytes {
                requested,
                available,
            } => {
                write!(
                    f,
                    "Insufficient bytes: requested {}, available {}",
                    requested, available
                )
            }
            Self::InsufficientOps {
                requested,
                available,
            } => {
                write!(
                    f,
                    "Insufficient ops: requested {}, available {}",
                    requested, available
                )
            }
            Self::ZeroQuota => write!(f, "Zero quota not allowed"),
        }
    }
}
