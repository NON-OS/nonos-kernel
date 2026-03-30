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

impl MmuError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "MMU not initialized",
            Self::NxNotSupported => "NXE not supported by CPU",
            Self::FrameAllocationFailed => "Failed to allocate page table frame",
            Self::WXViolation => "W^X violation: requested RW+X",
            Self::NotMapped => "Not mapped",
            Self::NoPageTableLoaded => "No page table loaded",
            Self::AlreadyInitialized => "Already initialized",
        }
    }

    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::NxNotSupported | Self::FrameAllocationFailed | Self::NoPageTableLoaded)
    }

    pub fn is_security_violation(&self) -> bool {
        matches!(self, Self::WXViolation)
    }
}
