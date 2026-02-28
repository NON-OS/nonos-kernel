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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MouseButton {
    Left = 0,
    Right = 1,
    Middle = 2,
    Button4 = 3,
    Button5 = 4,
}

impl MouseButton {
    pub const fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::Left),
            1 => Some(Self::Right),
            2 => Some(Self::Middle),
            3 => Some(Self::Button4),
            4 => Some(Self::Button5),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MouseButtons {
    bits: u8,
}

impl MouseButtons {
    pub const NONE: Self = Self { bits: 0 };
    pub const LEFT: u8 = 1 << 0;
    pub const RIGHT: u8 = 1 << 1;
    pub const MIDDLE: u8 = 1 << 2;
    pub const BUTTON4: u8 = 1 << 3;
    pub const BUTTON5: u8 = 1 << 4;

    #[inline]
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        Self { bits }
    }

    #[inline]
    pub const fn bits(self) -> u8 {
        self.bits
    }

    #[inline]
    pub const fn left(self) -> bool {
        (self.bits & Self::LEFT) != 0
    }

    #[inline]
    pub const fn right(self) -> bool {
        (self.bits & Self::RIGHT) != 0
    }

    #[inline]
    pub const fn middle(self) -> bool {
        (self.bits & Self::MIDDLE) != 0
    }

    #[inline]
    pub fn set(&mut self, button: MouseButton) {
        self.bits |= 1 << (button as u8);
    }

    #[inline]
    pub fn clear(&mut self, button: MouseButton) {
        self.bits &= !(1 << (button as u8));
    }

    #[inline]
    pub const fn is_pressed(self, button: MouseButton) -> bool {
        (self.bits & (1 << (button as u8))) != 0
    }
}
