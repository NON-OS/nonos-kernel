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

use super::types::RegionError;

impl RegionError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Region manager not initialized",
            Self::Overlapping => "Region overlaps with existing region",
            Self::NotFound => "Region not found",
            Self::NoFreeRegion => "No suitable free region found",
            Self::InvalidSplitOffset => "Split offset beyond region size",
            Self::InvalidSize => "Invalid region size",
            Self::InvalidAlignment => "Invalid alignment",
            Self::AlreadyExists => "Region already exists",
            Self::TypeMismatch => "Cannot merge regions of different types",
            Self::Protected => "Region is protected",
            Self::Locked => "Region is locked",
        }
    }

    pub const fn is_fatal(&self) -> bool {
        matches!(self, Self::NotInitialized | Self::NoFreeRegion)
    }

    pub const fn is_recoverable(&self) -> bool {
        matches!(self, Self::Overlapping | Self::NotFound | Self::InvalidSplitOffset)
    }
}
