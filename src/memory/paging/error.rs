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

//! Paging Error Types

use core::fmt;

/// Errors from paging operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingError {
    /// Paging manager not initialized
    NotInitialized,

    /// No active page table loaded
    NoActivePageTable,

    /// Failed to allocate page table frame
    FrameAllocationFailed,

    /// Page not mapped
    PageNotMapped,

    /// PML4 entry not present
    Pml4NotPresent,

    /// PDPT entry not present
    PdptNotPresent,

    /// PD entry not present
    PdNotPresent,

    /// PT entry not present
    PtNotPresent,

    /// Address space not found
    AddressSpaceNotFound,

    /// Invalid virtual address
    InvalidAddress,

    /// W^X violation: page cannot be both writable and executable
    WXViolation,

    /// Page already mapped
    AlreadyMapped,

    /// Permission denied
    PermissionDenied,

    /// Unhandled page fault
    UnhandledPageFault,

    /// Copy-on-write fault handling failed
    CowFaultFailed,

    /// Demand fault handling failed
    DemandFaultFailed,

    /// Invalid page size
    InvalidPageSize,

    /// Address not page-aligned
    NotAligned,

    /// Kernel space violation (user tried to access kernel memory)
    KernelSpaceViolation,
}

impl PagingError {
    /// Returns a human-readable description.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Paging manager not initialized",
            Self::NoActivePageTable => "No active page table",
            Self::FrameAllocationFailed => "Failed to allocate page table frame",
            Self::PageNotMapped => "Page not mapped",
            Self::Pml4NotPresent => "PML4 entry not present",
            Self::PdptNotPresent => "PDPT entry not present",
            Self::PdNotPresent => "PD entry not present",
            Self::PtNotPresent => "PT entry not present",
            Self::AddressSpaceNotFound => "Address space not found",
            Self::InvalidAddress => "Invalid virtual address",
            Self::WXViolation => "W^X violation: RW+X not allowed",
            Self::AlreadyMapped => "Page already mapped",
            Self::PermissionDenied => "Permission denied",
            Self::UnhandledPageFault => "Unhandled page fault",
            Self::CowFaultFailed => "Copy-on-write fault failed",
            Self::DemandFaultFailed => "Demand fault failed",
            Self::InvalidPageSize => "Invalid page size",
            Self::NotAligned => "Address not page-aligned",
            Self::KernelSpaceViolation => "Kernel space violation",
        }
    }

    /// Returns true if this error is fatal (system cannot continue).
    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::NoActivePageTable
                | Self::FrameAllocationFailed
                | Self::KernelSpaceViolation
        )
    }

    /// Returns true if this is a security violation.
    pub const fn is_security_violation(&self) -> bool {
        matches!(
            self,
            Self::WXViolation
                | Self::PermissionDenied
                | Self::KernelSpaceViolation
        )
    }

    /// Returns true if this error is recoverable.
    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::PageNotMapped
                | Self::Pml4NotPresent
                | Self::PdptNotPresent
                | Self::PdNotPresent
                | Self::PtNotPresent
        )
    }

    /// Returns true if the page fault can be handled by demand paging.
    pub const fn is_demand_pageable(&self) -> bool {
        matches!(
            self,
            Self::PageNotMapped
                | Self::Pml4NotPresent
                | Self::PdptNotPresent
                | Self::PdNotPresent
                | Self::PtNotPresent
        )
    }
}

impl fmt::Display for PagingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result type for paging operations.
pub type PagingResult<T> = Result<T, PagingError>;

impl From<&'static str> for PagingError {
    fn from(s: &'static str) -> Self {
        match s {
            "Paging manager not initialized" => Self::NotInitialized,
            "No active page table" => Self::NoActivePageTable,
            "Failed to allocate page table frame"
            | "Failed to allocate L3 table"
            | "Failed to allocate L2 table"
            | "Failed to allocate L1 table"
            | "Failed to allocate frame for COW"
            | "Failed to allocate frame for demand fault" => Self::FrameAllocationFailed,
            "Page not mapped" | "Page not present" => Self::PageNotMapped,
            "L4 entry not present" | "PML4 entry not present" => Self::Pml4NotPresent,
            "L3 entry not present" | "PDPT entry not present" => Self::PdptNotPresent,
            "L2 entry not present" | "PD entry not present" => Self::PdNotPresent,
            "L1 entry not present" | "PT entry not present" => Self::PtNotPresent,
            "Address space not found" => Self::AddressSpaceNotFound,
            "Invalid virtual address" => Self::InvalidAddress,
            "W^X violation" | "W^X violation: RW+X not allowed" => Self::WXViolation,
            "Page already mapped" => Self::AlreadyMapped,
            "Permission denied" => Self::PermissionDenied,
            "Unhandled page fault" => Self::UnhandledPageFault,
            _ => Self::NotInitialized,
        }
    }
}

/// Page fault information for error handling.
#[derive(Debug, Clone, Copy)]
pub struct PageFaultInfo {
    /// Faulting virtual address
    pub address: u64,
    /// Error code from CPU
    pub error_code: u64,
    /// Was it a write access
    pub is_write: bool,
    /// Was it a user-mode access
    pub is_user: bool,
    /// Was it an instruction fetch
    pub is_instruction_fetch: bool,
    /// Was the page present (protection fault vs not-present)
    pub page_was_present: bool,
}

impl PageFaultInfo {
    /// Creates fault info from address and error code.
    pub const fn from_fault(address: u64, error_code: u64) -> Self {
        Self {
            address,
            error_code,
            is_write: error_code & 0x02 != 0,
            is_user: error_code & 0x04 != 0,
            is_instruction_fetch: error_code & 0x10 != 0,
            page_was_present: error_code & 0x01 != 0,
        }
    }

    /// Returns true if this is a copy-on-write fault.
    pub const fn is_cow_fault(&self) -> bool {
        self.page_was_present && self.is_write
    }

    /// Returns true if this could be a demand-page fault.
    pub const fn is_demand_fault(&self) -> bool {
        !self.page_was_present
    }
}
