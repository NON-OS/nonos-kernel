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

//! Console driver error types.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleError {
    NotInitialized,
    InvalidPosition,
    BufferFull,
    InvalidColor,
    InvalidDimensions,
    ScrollFailed,
    ClearFailed,
    OutputFailed,
}

impl ConsoleError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Console not initialized",
            Self::InvalidPosition => "Invalid cursor position",
            Self::BufferFull => "Console buffer full",
            Self::InvalidColor => "Invalid color value",
            Self::InvalidDimensions => "Invalid console dimensions",
            Self::ScrollFailed => "Scroll operation failed",
            Self::ClearFailed => "Clear operation failed",
            Self::OutputFailed => "Output operation failed",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::BufferFull | Self::InvalidPosition
        )
    }
}

impl fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type Result<T> = core::result::Result<T, ConsoleError>;
