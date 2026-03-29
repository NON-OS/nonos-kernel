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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffError {
    NullPointer,
    InvalidMagic,
    VersionMismatch { expected: u16, got: u16 },
    SizeMismatch { expected: u16, got: u16 },
    AlreadyInitialized,
    InvalidData,
}

impl HandoffError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NullPointer => "Null handoff pointer",
            Self::InvalidMagic => "Invalid handoff magic value",
            Self::VersionMismatch { .. } => "Handoff version mismatch",
            Self::SizeMismatch { .. } => "Handoff size mismatch",
            Self::AlreadyInitialized => "Handoff already initialized",
            Self::InvalidData => "Invalid handoff data",
        }
    }
}

impl core::fmt::Display for HandoffError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VersionMismatch { expected, got } => {
                write!(f, "Handoff version mismatch: expected {}, got {}", expected, got)
            }
            Self::SizeMismatch { expected, got } => {
                write!(f, "Handoff size mismatch: expected {}, got {}", expected, got)
            }
            _ => write!(f, "{}", self.as_str()),
        }
    }
}
