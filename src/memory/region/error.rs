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
pub enum RegionError {
    NotInitialized,
    Overlapping,
    NotFound,
    NoFreeRegion,
    InvalidSplitOffset,
    InvalidSize,
    InvalidAlignment,
    AlreadyExists,
    TypeMismatch,
    Protected,
    Locked,
}

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
        matches!(
            self,
            Self::Overlapping | Self::NotFound | Self::InvalidSplitOffset
        )
    }
}

impl fmt::Display for RegionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type RegionResult<T> = Result<T, RegionError>;
impl From<&'static str> for RegionError {
    fn from(s: &'static str) -> Self {
        match s {
            "Region manager not initialized" => Self::NotInitialized,
            "Region overlaps with existing region" => Self::Overlapping,
            "Region not found" => Self::NotFound,
            "No suitable free region found" => Self::NoFreeRegion,
            "Split offset beyond region size" => Self::InvalidSplitOffset,
            "Invalid region size" => Self::InvalidSize,
            "Cannot merge regions of different types" => Self::TypeMismatch,
            "Region is protected" => Self::Protected,
            "Region is locked" => Self::Locked,
            _ => Self::NotInitialized,
        }
    }
}
