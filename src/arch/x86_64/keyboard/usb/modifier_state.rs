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
pub struct ModifierState {
    pub left_ctrl: bool, pub left_shift: bool, pub left_alt: bool, pub left_gui: bool,
    pub right_ctrl: bool, pub right_shift: bool, pub right_alt: bool, pub right_gui: bool,
}

impl ModifierState {
    pub const fn from_byte(b: u8) -> Self {
        Self { left_ctrl: (b & 0x01) != 0, left_shift: (b & 0x02) != 0, left_alt: (b & 0x04) != 0,
               left_gui: (b & 0x08) != 0, right_ctrl: (b & 0x10) != 0, right_shift: (b & 0x20) != 0,
               right_alt: (b & 0x40) != 0, right_gui: (b & 0x80) != 0 }
    }
    pub const fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.left_ctrl { b |= 0x01; } if self.left_shift { b |= 0x02; }
        if self.left_alt { b |= 0x04; } if self.left_gui { b |= 0x08; }
        if self.right_ctrl { b |= 0x10; } if self.right_shift { b |= 0x20; }
        if self.right_alt { b |= 0x40; } if self.right_gui { b |= 0x80; }
        b
    }
    pub const fn shift(self) -> bool { self.left_shift || self.right_shift }
    pub const fn ctrl(self) -> bool { self.left_ctrl || self.right_ctrl }
    pub const fn alt(self) -> bool { self.left_alt || self.right_alt }
    pub const fn gui(self) -> bool { self.left_gui || self.right_gui }
    pub const fn altgr(self) -> bool { self.right_alt }
}
