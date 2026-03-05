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

//! Memory Safety Error Types

use core::fmt;

/// Memory safety error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    /// Safety system not initialized.
    NotInitialized,
    /// Null pointer access attempted.
    NullPointer,
    /// Address calculation overflowed.
    AddressOverflow,
    /// Memory access with bad alignment.
    BadAlignment,
    /// Access to unmapped memory region.
    UnmappedAccess,
    /// Read access to non-readable region.
    ReadViolation,
    /// Write access to non-writable region.
    WriteViolation,
    /// Execute access to non-executable region.
    ExecuteViolation,
    /// Memory corruption detected.
    CorruptionDetected,
}

impl MemoryError {
    /// Returns a human-readable description.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Memory safety not initialized",
            Self::NullPointer => "Null pointer access",
            Self::AddressOverflow => "Address overflow",
            Self::BadAlignment => "Bad memory alignment",
            Self::UnmappedAccess => "Access to unmapped memory",
            Self::ReadViolation => "Read access violation",
            Self::WriteViolation => "Write access violation",
            Self::ExecuteViolation => "Execute access violation",
            Self::CorruptionDetected => "Memory corruption detected",
        }
    }

    /// Returns true if this error is a security violation.
    pub const fn is_security_violation(&self) -> bool {
        matches!(
            self,
            Self::ReadViolation
                | Self::WriteViolation
                | Self::ExecuteViolation
                | Self::CorruptionDetected
        )
    }

    /// Returns true if this error indicates potential attack.
    pub const fn is_potential_attack(&self) -> bool {
        matches!(
            self,
            Self::NullPointer | Self::AddressOverflow | Self::CorruptionDetected
        )
    }

    /// Returns true if this error is recoverable.
    pub const fn is_recoverable(&self) -> bool {
        matches!(self, Self::NotInitialized | Self::BadAlignment)
    }
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result type for memory safety operations.
pub type SafetyResult<T> = Result<T, MemoryError>;
