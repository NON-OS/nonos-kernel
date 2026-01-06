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
// along with this program. If not, see <https://www.gnu.org/licenses/>

use core::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageAllocError {
    NotInitialized,
    InvalidSize,
    FrameAllocationFailed,
    MappingFailed,
    PageNotFound,
    UnmapFailed,
    TranslationFailed,
    TooManyPages,
    OutOfVirtualSpace,
    AlreadyInitialized,
}

impl PageAllocError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Page allocator not initialized",
            Self::InvalidSize => "Invalid allocation size",
            Self::FrameAllocationFailed => "Failed to allocate physical frame",
            Self::MappingFailed => "Failed to map virtual page",
            Self::PageNotFound => "Page not found",
            Self::UnmapFailed => "Failed to unmap virtual page",
            Self::TranslationFailed => "Address translation failed",
            Self::TooManyPages => "Maximum pages exceeded",
            Self::OutOfVirtualSpace => "Out of virtual address space",
            Self::AlreadyInitialized => "Already initialized",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::FrameAllocationFailed | Self::OutOfVirtualSpace | Self::AlreadyInitialized
        )
    }
}

impl fmt::Display for PageAllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type PageAllocResult<T> = Result<T, PageAllocError>;
impl From<&'static str> for PageAllocError {
    fn from(s: &'static str) -> Self {
        match s {
            "Page allocator not initialized" => Self::NotInitialized,
            "Invalid allocation size" => Self::InvalidSize,
            "Failed to allocate physical frame" => Self::FrameAllocationFailed,
            "Failed to map page" => Self::MappingFailed,
            "Page not found" => Self::PageNotFound,
            "Failed to unmap page" => Self::UnmapFailed,
            "Address translation failed" => Self::TranslationFailed,
            _ => Self::NotInitialized,
        }
    }
}
