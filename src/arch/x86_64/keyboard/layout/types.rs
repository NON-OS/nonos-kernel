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

#[derive(Debug, Clone, Copy)]
pub struct LayoutInfo {
    pub layout: Layout,
    pub base: &'static [u8; 128],
    pub shift: &'static [u8; 128],
    pub altgr: &'static [u8; 128],
    pub dead_keys_base: &'static [(u8, DeadKey)],
    pub dead_keys_shift: &'static [(u8, DeadKey)],
}

impl LayoutInfo {
    pub const fn new(
        layout: Layout,
        base: &'static [u8; 128],
        shift: &'static [u8; 128],
        altgr: &'static [u8; 128],
    ) -> Self {
        Self {
            layout,
            base,
            shift,
            altgr,
            dead_keys_base: &[],
            dead_keys_shift: &[],
        }
    }

    pub const fn with_dead_keys(
        layout: Layout,
        base: &'static [u8; 128],
        shift: &'static [u8; 128],
        altgr: &'static [u8; 128],
        dead_base: &'static [(u8, DeadKey)],
        dead_shift: &'static [(u8, DeadKey)],
    ) -> Self {
        Self {
            layout,
            base,
            shift,
            altgr,
            dead_keys_base: dead_base,
            dead_keys_shift: dead_shift,
        }
    }

    pub fn lookup(&self, scan_code: u8, shifted: bool, altgr: bool) -> u8 {
        if scan_code >= 128 {
            return 0;
        }
        let idx = scan_code as usize;
        if altgr && self.altgr[idx] != 0 {
            self.altgr[idx]
        } else if shifted {
            self.shift[idx]
        } else {
            self.base[idx]
        }
    }

    pub fn is_dead_key(&self, scan_code: u8, shifted: bool) -> Option<DeadKey> {
        let table = if shifted { self.dead_keys_shift } else { self.dead_keys_base };
        for &(sc, dk) in table {
            if sc == scan_code {
                return Some(dk);
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeadKey {
    Acute = 1,
    Grave = 2,
    Circumflex = 3,
    Diaeresis = 4,
    Tilde = 5,
    Cedilla = 6,
    Ring = 7,
    Caron = 8,
}

impl DeadKey {
    pub const fn compose(self, base: u8) -> Option<u8> {
        match self {
            Self::Acute => match base {
                b'a' => Some(0xE1),
                b'e' => Some(0xE9),
                b'i' => Some(0xED),
                b'o' => Some(0xF3),
                b'u' => Some(0xFA),
                b'A' => Some(0xC1),
                b'E' => Some(0xC9),
                b'I' => Some(0xCD),
                b'O' => Some(0xD3),
                b'U' => Some(0xDA),
                b'y' => Some(0xFD),
                b'Y' => Some(0xDD),
                b' ' => Some(0xB4),
                _ => None,
            },
            Self::Grave => match base {
                b'a' => Some(0xE0),
                b'e' => Some(0xE8),
                b'i' => Some(0xEC),
                b'o' => Some(0xF2),
                b'u' => Some(0xF9),
                b'A' => Some(0xC0),
                b'E' => Some(0xC8),
                b'I' => Some(0xCC),
                b'O' => Some(0xD2),
                b'U' => Some(0xD9),
                b' ' => Some(b'`'),
                _ => None,
            },
            Self::Circumflex => match base {
                b'a' => Some(0xE2),
                b'e' => Some(0xEA),
                b'i' => Some(0xEE),
                b'o' => Some(0xF4),
                b'u' => Some(0xFB),
                b'A' => Some(0xC2),
                b'E' => Some(0xCA),
                b'I' => Some(0xCE),
                b'O' => Some(0xD4),
                b'U' => Some(0xDB),
                b' ' => Some(b'^'),
                _ => None,
            },
            Self::Diaeresis => match base {
                b'a' => Some(0xE4),
                b'e' => Some(0xEB),
                b'i' => Some(0xEF),
                b'o' => Some(0xF6),
                b'u' => Some(0xFC),
                b'y' => Some(0xFF),
                b'A' => Some(0xC4),
                b'E' => Some(0xCB),
                b'I' => Some(0xCF),
                b'O' => Some(0xD6),
                b'U' => Some(0xDC),
                b' ' => Some(0xA8),
                _ => None,
            },
            Self::Tilde => match base {
                b'a' => Some(0xE3),
                b'n' => Some(0xF1),
                b'o' => Some(0xF5),
                b'A' => Some(0xC3),
                b'N' => Some(0xD1),
                b'O' => Some(0xD5),
                b' ' => Some(b'~'),
                _ => None,
            },
            Self::Cedilla => match base {
                b'c' => Some(0xE7),
                b'C' => Some(0xC7),
                b' ' => Some(0xB8),
                _ => None,
            },
            Self::Ring => match base {
                b'a' => Some(0xE5),
                b'A' => Some(0xC5),
                b' ' => Some(0xB0),
                _ => None,
            },
            Self::Caron => match base {
                b'c' => Some(b'c'),
                b's' => Some(b's'),
                b'z' => Some(b'z'),
                b'C' => Some(b'C'),
                b'S' => Some(b'S'),
                b'Z' => Some(b'Z'),
                b' ' => Some(b'^'),
                _ => None,
            },
        }
    }

    pub const fn standalone(self) -> u8 {
        match self {
            Self::Acute => 0xB4,
            Self::Grave => b'`',
            Self::Circumflex => b'^',
            Self::Diaeresis => 0xA8,
            Self::Tilde => b'~',
            Self::Cedilla => 0xB8,
            Self::Ring => 0xB0,
            Self::Caron => b'^',
        }
    }
}
