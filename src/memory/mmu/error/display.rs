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

use super::types::MmuError;
use core::fmt;

impl fmt::Display for MmuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<&'static str> for MmuError {
    fn from(s: &'static str) -> Self {
        match s {
            "MMU not initialized" => Self::NotInitialized,
            "NXE not supported by CPU" => Self::NxNotSupported,
            "Failed to allocate page table frame" => Self::FrameAllocationFailed,
            "W^X violation: requested RW+X" | "W^X violation: RW+X not allowed" => {
                Self::WXViolation
            }
            "Not mapped" => Self::NotMapped,
            "No page table loaded" | "CR3 not initialized" => Self::NoPageTableLoaded,
            _ => Self::NotInitialized,
        }
    }
}
