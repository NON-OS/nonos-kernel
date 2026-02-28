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
pub enum Layout {
    UsQwerty = 0,
    Dvorak = 1,
    Azerty = 2,
    Colemak = 3,
    Qwertz = 4,
    UkQwerty = 5,
    Spanish = 6,
    Custom = 255,
}

impl Layout {
    pub const COUNT: usize = 7;

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::UsQwerty),
            1 => Some(Self::Dvorak),
            2 => Some(Self::Azerty),
            3 => Some(Self::Colemak),
            4 => Some(Self::Qwertz),
            5 => Some(Self::UkQwerty),
            6 => Some(Self::Spanish),
            255 => Some(Self::Custom),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::UsQwerty => "US QWERTY",
            Self::Dvorak => "Dvorak",
            Self::Azerty => "AZERTY (French)",
            Self::Colemak => "Colemak",
            Self::Qwertz => "QWERTZ (German)",
            Self::UkQwerty => "UK QWERTY",
            Self::Spanish => "Spanish QWERTY",
            Self::Custom => "Custom",
        }
    }

    pub const fn language_code(self) -> &'static str {
        match self {
            Self::UsQwerty | Self::Dvorak | Self::Colemak | Self::UkQwerty => "en",
            Self::Azerty => "fr",
            Self::Qwertz => "de",
            Self::Spanish => "es",
            Self::Custom => "xx",
        }
    }

    pub const fn country_code(self) -> &'static str {
        match self {
            Self::UsQwerty | Self::Dvorak | Self::Colemak => "US",
            Self::UkQwerty => "GB",
            Self::Azerty => "FR",
            Self::Qwertz => "DE",
            Self::Spanish => "ES",
            Self::Custom => "XX",
        }
    }

    pub const fn has_altgr(self) -> bool {
        matches!(self, Self::Azerty | Self::Qwertz | Self::Spanish | Self::UkQwerty)
    }

    pub const fn has_dead_keys(self) -> bool {
        matches!(self, Self::Azerty | Self::Qwertz | Self::Spanish)
    }

    pub const fn all() -> [Layout; Self::COUNT] {
        [
            Self::UsQwerty,
            Self::Dvorak,
            Self::Azerty,
            Self::Colemak,
            Self::Qwertz,
            Self::UkQwerty,
            Self::Spanish,
        ]
    }
}

impl Default for Layout {
    fn default() -> Self {
        Self::UsQwerty
    }
}
