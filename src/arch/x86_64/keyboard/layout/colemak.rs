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
    0,    27,   b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 8,    b'\t',
    b'q', b'w', b'f', b'p', b'g', b'j', b'l', b'u', b'y', b';', b'[', b']', b'\n', 0,   b'a', b'r',
    b's', b't', b'd', b'h', b'n', b'e', b'i', b'o', b'\'',b'`', 0,    b'\\',b'z', b'x', b'c', b'v',
    b'b', b'k', b'm', b',', b'.', b'/', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub static SHIFT: [u8; 128] = [
    0,    27,   b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'_', b'+', 8,    b'\t',
    b'Q', b'W', b'F', b'P', b'G', b'J', b'L', b'U', b'Y', b':', b'{', b'}', b'\n', 0,   b'A', b'R',
    b'S', b'T', b'D', b'H', b'N', b'E', b'I', b'O', b'"', b'~', 0,    b'|', b'Z', b'X', b'C', b'V',
    b'B', b'K', b'M', b'<', b'>', b'?', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

static ALTGR: [u8; 128] = [0; 128];

pub static LAYOUT_INFO: LayoutInfo = LayoutInfo::new(Layout::Colemak, &BASE, &SHIFT, &ALTGR);
