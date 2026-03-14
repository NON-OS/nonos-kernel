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

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayError {
    NotInitialized,
    InvalidAddress,
    OutOfBounds,
    InvalidFormat,
    NoFramebuffer,
}

impl fmt::Display for DisplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => write!(f, "display not initialized"),
            Self::InvalidAddress => write!(f, "invalid framebuffer address"),
            Self::OutOfBounds => write!(f, "coordinates out of bounds"),
            Self::InvalidFormat => write!(f, "invalid pixel format"),
            Self::NoFramebuffer => write!(f, "no framebuffer registered"),
        }
    }
}
