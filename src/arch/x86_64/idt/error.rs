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
pub enum IdtError {
    None = 0,
    NotInitialized = 1,
    AlreadyInitialized = 2,
    InvalidVector = 3,
    InvalidIstIndex = 4,
    NullHandler = 5,
    LoadFailed = 6,
    HandlerExists = 7,
    ReservedVector = 8,
}

impl IdtError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "no error",
            Self::NotInitialized => "IDT not initialized",
            Self::AlreadyInitialized => "IDT already initialized",
            Self::InvalidVector => "invalid interrupt vector number",
            Self::InvalidIstIndex => "IST index must be 0-7",
            Self::NullHandler => "handler address is null",
            Self::LoadFailed => "IDT load failed",
            Self::HandlerExists => "handler already registered for this vector",
            Self::ReservedVector => "cannot modify reserved vector",
        }
    }
}
