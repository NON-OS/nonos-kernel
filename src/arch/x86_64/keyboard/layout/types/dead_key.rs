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
