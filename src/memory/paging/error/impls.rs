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

use super::types::PagingError;

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
            Self::NoActivePageTable | Self::FrameAllocationFailed | Self::KernelSpaceViolation
        )
    }

    pub const fn is_security_violation(&self) -> bool {
        matches!(self, Self::WXViolation | Self::PermissionDenied | Self::KernelSpaceViolation)
    }
}
