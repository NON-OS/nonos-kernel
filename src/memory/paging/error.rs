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
pub enum PagingError {
    NotInitialized,
    NoActivePageTable,
    FrameAllocationFailed,
    PageNotMapped,
    Pml4NotPresent,
    PdptNotPresent,
    PdNotPresent,
    PtNotPresent,
    AddressSpaceNotFound,
    InvalidAddress,
    WXViolation,
    AlreadyMapped,
    PermissionDenied,
    UnhandledPageFault,
    CowFaultFailed,
    DemandFaultFailed,
    InvalidPageSize,
    NotAligned,
    KernelSpaceViolation,
}

impl PagingError {
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

    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::NoActivePageTable
                | Self::FrameAllocationFailed
                | Self::KernelSpaceViolation
        )
    }

    pub const fn is_security_violation(&self) -> bool {
        matches!(
            self,
            Self::WXViolation
                | Self::PermissionDenied
                | Self::KernelSpaceViolation
        )
    }

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

#[derive(Debug, Clone, Copy)]
pub struct PageFaultInfo {
    pub address: u64,
    pub error_code: u64,
    pub is_write: bool,
    pub is_user: bool,
    pub is_instruction_fetch: bool,
    pub page_was_present: bool,
}

impl PageFaultInfo {
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

    pub const fn is_cow_fault(&self) -> bool {
        self.page_was_present && self.is_write
    }

    pub const fn is_demand_fault(&self) -> bool {
        !self.page_was_present
    }
}
