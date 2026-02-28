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

use super::modifiers::Modifiers;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LedState {
    bits: u8,
}

impl LedState {
    pub const NONE: Self = Self { bits: 0 };
    pub const SCROLL_LOCK: u8 = 1 << 0;
    pub const NUM_LOCK: u8 = 1 << 1;
    pub const CAPS_LOCK: u8 = 1 << 2;

    #[inline]
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        Self { bits: bits & 0x07 }
    }

    #[inline]
    pub const fn bits(self) -> u8 {
        self.bits
    }

    #[inline]
    pub const fn scroll_lock(self) -> bool {
        (self.bits & Self::SCROLL_LOCK) != 0
    }

    #[inline]
    pub const fn num_lock(self) -> bool {
        (self.bits & Self::NUM_LOCK) != 0
    }

    #[inline]
    pub const fn caps_lock(self) -> bool {
        (self.bits & Self::CAPS_LOCK) != 0
    }

    #[inline]
    pub fn set(&mut self, flag: u8) {
        self.bits |= flag & 0x07;
    }

    #[inline]
    pub fn clear(&mut self, flag: u8) {
        self.bits &= !flag;
    }

    #[inline]
    pub fn toggle(&mut self, flag: u8) {
        self.bits ^= flag & 0x07;
    }

    pub fn from_modifiers(mods: Modifiers) -> Self {
        let mut leds = Self::new();
        if mods.caps_lock() {
            leds.set(Self::CAPS_LOCK);
        }
        if mods.num_lock() {
            leds.set(Self::NUM_LOCK);
        }
        if mods.scroll_lock() {
            leds.set(Self::SCROLL_LOCK);
        }
        leds
    }
}
