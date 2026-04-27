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
        matches!(self, Self::InternalCorruption | Self::RegionNotFound | Self::AddressNotFound)
    }

    pub fn is_retriable(&self) -> bool {
        matches!(self, Self::AllocationFailed)
    }
}
