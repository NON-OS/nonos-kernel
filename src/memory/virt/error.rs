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
pub enum VmError {
    NotInitialized,
    OutOfMemory,
    InvalidAlignment,
    AddressNotMapped,
    PermissionViolation,
    InvalidRange,
    PageTableError,
    FrameAllocationFailed,
    AddressAlreadyMapped,
    WXViolation,
}

impl VmError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Virtual memory manager not initialized",
            Self::OutOfMemory => "Out of physical memory for page tables",
            Self::InvalidAlignment => "Invalid alignment for mapping",
            Self::AddressNotMapped => "Address not mapped",
            Self::PermissionViolation => "Permission violation",
            Self::InvalidRange => "Invalid memory range",
            Self::PageTableError => "Page table structure error",
            Self::FrameAllocationFailed => "Frame allocation failed",
            Self::AddressAlreadyMapped => "Address already mapped",
            Self::WXViolation => "Cannot map memory as both writable and executable",
        }
    }

    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::OutOfMemory | Self::PageTableError | Self::FrameAllocationFailed
        )
    }

    pub fn is_security_violation(&self) -> bool {
        matches!(self, Self::PermissionViolation | Self::WXViolation)
    }
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type VmResult<T> = Result<T, VmError>;
