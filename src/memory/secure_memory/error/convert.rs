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
use core::fmt;

impl fmt::Display for SecureMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

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
