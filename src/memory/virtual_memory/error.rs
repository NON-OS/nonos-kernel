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

//! Virtual Memory Error Types

use core::fmt;

/// Virtual memory error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    /// Virtual memory manager not initialized.
    NotInitialized,
    /// Address space not found.
    AddressSpaceNotFound,
    /// VM area not found.
    VmAreaNotFound,
    /// VM area overlaps with existing area.
    Overlapping,
    /// Frame allocation failed.
    FrameAllocationFailed,
    /// Page mapping failed.
    PageMappingFailed,
    /// Write to read-only memory.
    WriteProtectionFault,
    /// Execute on non-executable memory.
    ExecuteProtectionFault,
    /// No VM area for fault address.
    NoVmAreaForAddress,
    /// Heap expansion failed.
    HeapExpansionFailed,
    /// Stack expansion failed.
    StackExpansionFailed,
    /// Invalid address.
    InvalidAddress,
}

impl VmError {
    /// Returns a human-readable description.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Virtual memory manager not initialized",
            Self::AddressSpaceNotFound => "Address space not found",
            Self::VmAreaNotFound => "VM area not found",
            Self::Overlapping => "VM area overlaps with existing area",
            Self::FrameAllocationFailed => "Failed to allocate physical frame",
            Self::PageMappingFailed => "Failed to map page",
            Self::WriteProtectionFault => "Write to read-only memory",
            Self::ExecuteProtectionFault => "Execute on non-executable memory",
            Self::NoVmAreaForAddress => "No VM area for fault address",
            Self::HeapExpansionFailed => "Heap expansion failed",
            Self::StackExpansionFailed => "Stack expansion failed",
            Self::InvalidAddress => "Invalid address",
        }
    }

    /// Returns true if this error is a protection fault.
    pub const fn is_protection_fault(&self) -> bool {
        matches!(
            self,
            Self::WriteProtectionFault | Self::ExecuteProtectionFault
        )
    }

    /// Returns true if this error is recoverable.
    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::NotInitialized | Self::Overlapping | Self::VmAreaNotFound
        )
    }

    /// Returns true if this error is fatal.
    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::WriteProtectionFault | Self::ExecuteProtectionFault
        )
    }
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result type for virtual memory operations.
pub type VmResult<T> = Result<T, VmError>;
