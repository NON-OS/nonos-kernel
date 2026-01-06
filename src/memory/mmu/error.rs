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
pub enum MmuError {
    NotInitialized,
    NxNotSupported,
    FrameAllocationFailed,
    WXViolation,
    NotMapped,
    NoPageTableLoaded,
    AlreadyInitialized,
}

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
        matches!(
            self,
            Self::NxNotSupported | Self::FrameAllocationFailed | Self::NoPageTableLoaded
        )
    }

    pub fn is_security_violation(&self) -> bool {
        matches!(self, Self::WXViolation)
    }
}

impl fmt::Display for MmuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type MmuResult<T> = Result<T, MmuError>;
impl From<&'static str> for MmuError {
    fn from(s: &'static str) -> Self {
        match s {
            "MMU not initialized" => Self::NotInitialized,
            "NXE not supported by CPU" => Self::NxNotSupported,
            "Failed to allocate page table frame" => Self::FrameAllocationFailed,
            "W^X violation: requested RW+X" | "W^X violation: RW+X not allowed" => Self::WXViolation,
            "Not mapped" => Self::NotMapped,
            "No page table loaded" | "CR3 not initialized" => Self::NoPageTableLoaded,
            _ => Self::NotInitialized,
        }
    }
}
