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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VgaError {
    None = 0,
    NotInitialized = 1,
    AlreadyInitialized = 2,
    InvalidConsole = 3,
    InvalidPosition = 4,
    LockContention = 5,
}

impl VgaError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "no error",
            Self::NotInitialized => "VGA not initialized",
            Self::AlreadyInitialized => "VGA already initialized",
            Self::InvalidConsole => "invalid console index",
            Self::InvalidPosition => "invalid cursor position",
            Self::LockContention => "VGA lock contention",
        }
    }
}
