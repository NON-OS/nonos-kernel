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

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Fill = 0,
    Fit = 1,
    Stretch = 2,
    Center = 3,
    Tile = 4,
}

impl Policy {
    pub fn from_u32(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Fill),
            1 => Some(Self::Fit),
            2 => Some(Self::Stretch),
            3 => Some(Self::Center),
            4 => Some(Self::Tile),
            _ => None,
        }
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }
}
