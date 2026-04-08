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

use super::command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AccessMode {
    Latch = 0,
    LowByte = 1,
    HighByte = 2,
    LowHigh = 3,
}

impl AccessMode {
    pub const fn bits(&self) -> u8 {
        match self {
            Self::Latch => command::ACCESS_LATCH,
            Self::LowByte => command::ACCESS_LOBYTE,
            Self::HighByte => command::ACCESS_HIBYTE,
            Self::LowHigh => command::ACCESS_LOHI,
        }
    }
}
