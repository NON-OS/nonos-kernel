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

use core::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureMemoryError {
    NotInitialized,
    AlreadyInitialized,
    InvalidSize,
    AllocationFailed,
    AddressNotFound,
    RegionNotFound,
    TranslationFailed,
    ZeroingFailed,
    AccessDenied,
    InvalidSecurityLevel,
    InvalidRegionType,
    RegionLimitExceeded,
    OwnershipViolation,
    WriteToReadOnly,
    ExecuteViolation,
    AlreadyDeallocated,
    InvalidAddress,
    SystemRegionProtected,
    InternalCorruption,
}

impl SecureMemoryError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Memory manager not initialized",
            Self::AlreadyInitialized => "Memory manager already initialized",
            Self::InvalidSize => "Invalid allocation size",
            Self::AllocationFailed => "Memory allocation failed",
            Self::AddressNotFound => "Address not found in managed regions",
            Self::RegionNotFound => "Region not found",
            Self::TranslationFailed => "Address translation failed",
            Self::ZeroingFailed => "Memory zeroing operation failed",
            Self::AccessDenied => "Access denied",
            Self::InvalidSecurityLevel => "Invalid security level",
            Self::InvalidRegionType => "Invalid region type",
            Self::RegionLimitExceeded => "Maximum region count exceeded",
            Self::OwnershipViolation => "Process ownership violation",
            Self::WriteToReadOnly => "Write access to read-only region",
            Self::ExecuteViolation => "Execute access to non-executable region",
            Self::AlreadyDeallocated => "Memory region already deallocated",
            Self::InvalidAddress => "Invalid virtual address",
            Self::SystemRegionProtected => "Cannot deallocate system region",
            Self::InternalCorruption => "Internal data structure corruption",
        }
    }

    pub fn is_security_critical(&self) -> bool {
        matches!(
            self,
            Self::AccessDenied
                | Self::OwnershipViolation
                | Self::WriteToReadOnly
                | Self::ExecuteViolation
                | Self::SystemRegionProtected
                | Self::InternalCorruption
        )
    }

    pub fn is_internal_error(&self) -> bool {
        matches!(
            self,
            Self::InternalCorruption | Self::RegionNotFound | Self::AddressNotFound
        )
    }

    pub fn is_retriable(&self) -> bool {
        matches!(self, Self::AllocationFailed)
    }
}

impl fmt::Display for SecureMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type SecureMemoryResult<T> = Result<T, SecureMemoryError>;
impl From<&'static str> for SecureMemoryError {
    fn from(s: &'static str) -> Self {
        match s {
            "Memory manager not initialized" => Self::NotInitialized,
            "Invalid allocation size" => Self::InvalidSize,
            "Address not found" => Self::AddressNotFound,
            "Region not found" => Self::RegionNotFound,
            "Address translation failed" => Self::TranslationFailed,
            "Access denied" => Self::AccessDenied,
            _ => Self::AllocationFailed,
        }
    }
}
