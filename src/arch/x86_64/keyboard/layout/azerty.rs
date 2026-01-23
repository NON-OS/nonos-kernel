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

use super::types::{DeadKey, Layout, LayoutInfo};

pub static BASE: [u8; 128] = [
    0,    27,   b'&', 0xE9, b'"', b'\'',b'(', b'-', 0xE8, b'_', 0xE7, 0xE0, b')', b'=', 8,    b'\t',
    b'a', b'z', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'^', b'$', b'\n', 0,   b'q', b's',
    b'd', b'f', b'g', b'h', b'j', b'k', b'l', b'm', 0xF9, 0xB2, 0,    b'*', b'w', b'x', b'c', b'v',
    b'b', b'n', b',', b';', b':', b'!', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub static SHIFT: [u8; 128] = [
    0,    27,   b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', 0xB0, b'+', 8,    b'\t',
    b'A', b'Z', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', 0xA8, 0xA3, b'\n', 0,   b'Q', b'S',
    b'D', b'F', b'G', b'H', b'J', b'K', b'L', b'M', b'%', b'~', 0,    0xB5, b'W', b'X', b'C', b'V',
    b'B', b'N', b'?', b'.', b'/', 0xA7, 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

static ALTGR: [u8; 128] = [
    0,    0,    0,    b'~', b'#', b'{', b'[', b'|', b'`', b'\\',b'^', b'@', b']', b'}', 0,    0,
    0,    0,    0x80, 0,    0,    0,    0,    0,    0,    0,    0,    0xA4, 0,    0,    0,    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

static DEAD_BASE: [(u8, DeadKey); 1] = [(0x1A, DeadKey::Circumflex)];
static DEAD_SHIFT: [(u8, DeadKey); 1] = [(0x1A, DeadKey::Diaeresis)];

pub static LAYOUT_INFO: LayoutInfo = LayoutInfo::with_dead_keys(
    Layout::Azerty,
    &BASE,
    &SHIFT,
    &ALTGR,
    &DEAD_BASE,
    &DEAD_SHIFT,
);
