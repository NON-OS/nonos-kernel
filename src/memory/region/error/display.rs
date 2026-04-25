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
use core::fmt;

impl fmt::Display for RegionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

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
