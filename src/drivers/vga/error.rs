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
pub enum VgaError {
    NotInitialized,
    InvalidMode,
    InvalidPosition,
    InvalidColor,
    OutOfBounds,
    UnsupportedOperation,
    HardwareError,
}

impl VgaError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "VGA not initialized",
            Self::InvalidMode => "Invalid VGA mode",
            Self::InvalidPosition => "Invalid position",
            Self::InvalidColor => "Invalid color attribute",
            Self::OutOfBounds => "Position out of bounds",
            Self::UnsupportedOperation => "Unsupported operation",
            Self::HardwareError => "VGA hardware error",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::InvalidPosition | Self::OutOfBounds
        )
    }
}

impl fmt::Display for VgaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type Result<T> = core::result::Result<T, VgaError>;
