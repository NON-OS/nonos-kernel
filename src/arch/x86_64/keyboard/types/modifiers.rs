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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Modifiers {
    bits: u8,
}

impl Modifiers {
    pub const NONE: Self = Self { bits: 0 };
    pub const SHIFT: u8 = 1 << 0;
    pub const CTRL: u8 = 1 << 1;
    pub const ALT: u8 = 1 << 2;
    pub const SUPER: u8 = 1 << 3;
    pub const CAPS_LOCK: u8 = 1 << 4;
    pub const NUM_LOCK: u8 = 1 << 5;
    pub const SCROLL_LOCK: u8 = 1 << 6;
    pub const ALTGR: u8 = 1 << 7;

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
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    #[inline]
    pub const fn shift(self) -> bool {
        (self.bits & Self::SHIFT) != 0
    }

    #[inline]
    pub const fn ctrl(self) -> bool {
        (self.bits & Self::CTRL) != 0
    }

    #[inline]
    pub const fn alt(self) -> bool {
        (self.bits & Self::ALT) != 0
    }

    #[inline]
    pub const fn super_key(self) -> bool {
        (self.bits & Self::SUPER) != 0
    }

    #[inline]
    pub const fn caps_lock(self) -> bool {
        (self.bits & Self::CAPS_LOCK) != 0
    }

    #[inline]
    pub const fn num_lock(self) -> bool {
        (self.bits & Self::NUM_LOCK) != 0
    }

    #[inline]
    pub const fn scroll_lock(self) -> bool {
        (self.bits & Self::SCROLL_LOCK) != 0
    }

    #[inline]
    pub const fn altgr(self) -> bool {
        (self.bits & Self::ALTGR) != 0
    }

    #[inline]
    pub const fn effective_shift(self) -> bool {
        let shift = (self.bits & Self::SHIFT) != 0;
        let caps = (self.bits & Self::CAPS_LOCK) != 0;
        shift ^ caps
    }

    #[inline]
    pub fn set(&mut self, flag: u8) {
        self.bits |= flag;
    }

    #[inline]
    pub fn clear(&mut self, flag: u8) {
        self.bits &= !flag;
    }

    #[inline]
    pub fn toggle(&mut self, flag: u8) {
        self.bits ^= flag;
    }

    #[inline]
    pub const fn contains(self, flag: u8) -> bool {
        (self.bits & flag) == flag
    }

    pub const fn with_shift(self) -> Self {
        Self { bits: self.bits | Self::SHIFT }
    }

    pub const fn with_ctrl(self) -> Self {
        Self { bits: self.bits | Self::CTRL }
    }

    pub const fn with_alt(self) -> Self {
        Self { bits: self.bits | Self::ALT }
    }
}
