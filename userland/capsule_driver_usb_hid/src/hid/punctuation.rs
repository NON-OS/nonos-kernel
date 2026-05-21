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

pub fn ascii_punctuation(scancode: u8, shifted: bool) -> u8 {
    match (scancode, shifted) {
        (0x2d, false) => b'-',
        (0x2d, true) => b'_',
        (0x2e, false) => b'=',
        (0x2e, true) => b'+',
        (0x2f, false) => b'[',
        (0x2f, true) => b'{',
        (0x30, false) => b']',
        (0x30, true) => b'}',
        (0x31, false) => b'\\',
        (0x31, true) => b'|',
        (0x33, false) => b';',
        (0x33, true) => b':',
        (0x34, false) => b'\'',
        (0x34, true) => b'"',
        (0x35, false) => b'`',
        (0x35, true) => b'~',
        (0x36, false) => b',',
        (0x36, true) => b'<',
        (0x37, false) => b'.',
        (0x37, true) => b'>',
        (0x38, false) => b'/',
        (0x38, true) => b'?',
        _ => 0,
    }
}
