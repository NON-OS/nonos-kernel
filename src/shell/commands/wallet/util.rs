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

use crate::graphics::framebuffer::COLOR_ACCENT;
use crate::shell::output::print_line;

pub(super) fn trim_bytes(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&c| c != b' ' && c != b'\t').unwrap_or(s.len());
    let end = s.iter().rposition(|&c| c != b' ' && c != b'\t').map(|i| i + 1).unwrap_or(0);
    if start < end { &s[start..end] } else { &[] }
}

pub(super) fn hex_char(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + n - 10 }
}

pub(super) fn print_hex32_out(data: &[u8; 32]) {
    let mut line = [0u8; 68];
    line[..2].copy_from_slice(b"  ");
    for i in 0..32 {
        line[2 + i * 2] = hex_char(data[i] >> 4);
        line[2 + i * 2 + 1] = hex_char(data[i] & 0xF);
    }
    print_line(&line[..66], COLOR_ACCENT);
}

