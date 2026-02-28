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
pub enum PicError {
    NotInitialized,
    Disabled,
    InvalidIrq,
    AlreadyInitialized,
}

impl PicError {
    pub const fn as_str(self) -> &'static str {
        match self {
            PicError::NotInitialized => "PIC not initialized",
            PicError::Disabled => "PIC has been disabled",
            PicError::InvalidIrq => "Invalid IRQ number (must be 0-15)",
            PicError::AlreadyInitialized => "PIC already initialized",
        }
    }
}

pub type PicResult<T> = Result<T, PicError>;
