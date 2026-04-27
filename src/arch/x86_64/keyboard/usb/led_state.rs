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
pub struct LedState {
    pub num_lock: bool,
    pub caps_lock: bool,
    pub scroll_lock: bool,
    pub compose: bool,
    pub kana: bool,
}

impl LedState {
    pub const fn new() -> Self {
        Self { num_lock: false, caps_lock: false, scroll_lock: false, compose: false, kana: false }
    }
    pub const fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.num_lock {
            b |= 0x01;
        }
        if self.caps_lock {
            b |= 0x02;
        }
        if self.scroll_lock {
            b |= 0x04;
        }
        if self.compose {
            b |= 0x08;
        }
        if self.kana {
            b |= 0x10;
        }
        b
    }
    pub const fn from_byte(b: u8) -> Self {
        Self {
            num_lock: (b & 0x01) != 0,
            caps_lock: (b & 0x02) != 0,
            scroll_lock: (b & 0x04) != 0,
            compose: (b & 0x08) != 0,
            kana: (b & 0x10) != 0,
        }
    }
}
