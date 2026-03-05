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

//! Secure Memory Manager Error Types
//!
//! Error types for secure memory allocation and management operations.

use core::fmt;

/// Errors that can occur during secure memory operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureMemoryError {
    /// Memory manager not initialized
    NotInitialized,

    /// Already initialized (double init attempt)
    AlreadyInitialized,

    /// Invalid allocation size (zero or too large)
    InvalidSize,

    /// Allocation failed (out of memory or mapping failed)
    AllocationFailed,

    /// Address not found in managed regions
    AddressNotFound,

    /// Region not found for the given ID
    RegionNotFound,

    /// Address translation failed
    TranslationFailed,

    /// Memory zeroing operation failed
    ZeroingFailed,

    /// Access denied (permission or ownership violation)
    AccessDenied,

    /// Invalid security level specified
    InvalidSecurityLevel,

    /// Invalid region type specified
    InvalidRegionType,

    /// Maximum region count exceeded
    RegionLimitExceeded,

    /// Process ID mismatch (ownership violation)
    OwnershipViolation,

    /// Write access to read-only region
    WriteToReadOnly,

    /// Execute access to non-executable region
    ExecuteViolation,

    /// Memory already deallocated
    AlreadyDeallocated,

    /// Invalid virtual address (null or non-canonical)
    InvalidAddress,

    /// Deallocation of system region not allowed
    SystemRegionProtected,

    /// Internal data structure corruption detected
    InternalCorruption,
}

impl SecureMemoryError {
    /// Returns a human-readable description of the error
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

    /// Returns true if this is a security-critical error
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

    /// Returns true if this error indicates a programming bug
    pub fn is_internal_error(&self) -> bool {
        matches!(
            self,
            Self::InternalCorruption | Self::RegionNotFound | Self::AddressNotFound
        )
    }

    /// Returns true if the operation should be retried
    pub fn is_retriable(&self) -> bool {
        matches!(self, Self::AllocationFailed)
    }
}

impl fmt::Display for SecureMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result type alias for secure memory operations
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
