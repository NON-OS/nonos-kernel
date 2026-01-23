// **
//Dr. Dvorak (Univ. of Washington, Seattle; he lived 1894–1975) used his research to design two other keyboards specifically for people with only one hand
// **
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

use super::types::{Layout, LayoutInfo};

pub static BASE: [u8; 128] = [
    0,    27,   b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'[', b']', 8,    b'\t',
    b'\'',b',', b'.', b'p', b'y', b'f', b'g', b'c', b'r', b'l', b'/', b'=', b'\n', 0,   b'a', b'o',
    b'e', b'u', b'i', b'd', b'h', b't', b'n', b's', b'-', b'`', 0,    b'\\',b';', b'q', b'j', b'k',
    b'x', b'b', b'm', b'w', b'v', b'z', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub static SHIFT: [u8; 128] = [
    0,    27,   b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'{', b'}', 8,    b'\t',
    b'"', b'<', b'>', b'P', b'Y', b'F', b'G', b'C', b'R', b'L', b'?', b'+', b'\n', 0,   b'A', b'O',
    b'E', b'U', b'I', b'D', b'H', b'T', b'N', b'S', b'_', b'~', 0,    b'|', b':', b'Q', b'J', b'K',
    b'X', b'B', b'M', b'W', b'V', b'Z', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

static ALTGR: [u8; 128] = [0; 128];

pub static LAYOUT_INFO: LayoutInfo = LayoutInfo::new(Layout::Dvorak, &BASE, &SHIFT, &ALTGR);
