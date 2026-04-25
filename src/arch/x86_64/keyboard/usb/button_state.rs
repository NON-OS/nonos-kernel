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

#[derive(Debug, Clone, Copy, Default)]
pub struct MouseButtonState {
    pub left: bool,
    pub right: bool,
    pub middle: bool,
    pub button4: bool,
    pub button5: bool,
}

impl MouseButtonState {
    pub const fn from_byte(b: u8) -> Self {
        Self {
            left: (b & 0x01) != 0,
            right: (b & 0x02) != 0,
            middle: (b & 0x04) != 0,
            button4: (b & 0x08) != 0,
            button5: (b & 0x10) != 0,
        }
    }
    pub const fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.left {
            b |= 0x01;
        }
        if self.right {
            b |= 0x02;
        }
        if self.middle {
            b |= 0x04;
        }
        if self.button4 {
            b |= 0x08;
        }
        if self.button5 {
            b |= 0x10;
        }
        b
    }
    pub const fn get(self, i: u8) -> bool {
        match i {
            0 => self.left,
            1 => self.right,
            2 => self.middle,
            3 => self.button4,
            4 => self.button5,
            _ => false,
        }
    }
}
