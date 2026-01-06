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
pub enum LayoutError {
    SlideNotAligned,
    KernelBaseTooLow,
    PercpuStrideMisaligned,
    WindowOverlap,
    OrderViolation,
    SizeExceedsCapacity,
    NotInKernelSpace,
    NotInUserSpace,
    InvalidAlignment,
    NotInitialized,
    ConfigLocked,
    InvalidRegionBounds,
}

impl LayoutError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SlideNotAligned => "KASLR slide not page-aligned",
            Self::KernelBaseTooLow => "Kernel base below higher-half",
            Self::PercpuStrideMisaligned => "Per-CPU stride misaligned",
            Self::WindowOverlap => "Layout windows overlap",
            Self::OrderViolation => "Layout region order violation",
            Self::SizeExceedsCapacity => "Requested size exceeds region capacity",
            Self::NotInKernelSpace => "Address not in kernel space",
            Self::NotInUserSpace => "Address not in user space",
            Self::InvalidAlignment => "Invalid alignment value",
            Self::NotInitialized => "Layout not initialized",
            Self::ConfigLocked => "Layout configuration locked",
            Self::InvalidRegionBounds => "Invalid region boundaries",
        }
    }

    pub fn is_config_error(&self) -> bool {
        matches!(
            self,
            Self::SlideNotAligned
                | Self::KernelBaseTooLow
                | Self::PercpuStrideMisaligned
                | Self::InvalidAlignment
                | Self::InvalidRegionBounds
        )
    }
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type LayoutResult<T> = Result<T, LayoutError>;
impl From<&'static str> for LayoutError {
    fn from(s: &'static str) -> Self {
        match s {
            "slide not page-aligned" => Self::SlideNotAligned,
            "kernel base below higher-half" => Self::KernelBaseTooLow,
            "percpu stride misaligned" => Self::PercpuStrideMisaligned,
            "layout window overlap" => Self::WindowOverlap,
            "layout order violation" => Self::OrderViolation,
            "request > heap size" => Self::SizeExceedsCapacity,
            _ => Self::NotInitialized,
        }
    }
}
