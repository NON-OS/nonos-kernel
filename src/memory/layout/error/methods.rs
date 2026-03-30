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

use super::types::LayoutError;

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
