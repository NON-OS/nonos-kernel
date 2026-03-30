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
