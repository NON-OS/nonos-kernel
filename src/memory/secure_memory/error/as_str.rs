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

use super::types::SecureMemoryError;

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
}
