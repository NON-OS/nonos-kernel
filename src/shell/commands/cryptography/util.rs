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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::COLOR_ACCENT;
use crate::shell::commands::utils::{trim_bytes, format_hex_byte};

pub(super) fn split_first_word(s: &[u8]) -> (&[u8], &[u8]) {
    let s = trim_bytes(s);
    match s.iter().position(|&c| c == b' ') {
        Some(pos) => (&s[..pos], trim_bytes(&s[pos + 1..])),
        None => (s, &[]),
    }
}

pub(super) fn print_hash_hex(hash: &[u8; 32]) {
    let mut line = [0u8; 68];
    line[0] = b' ';
    line[1] = b' ';

    for i in 0..32 {
        format_hex_byte(&mut line[2 + i * 2..], hash[i]);
    }

    print_line(&line[..66], COLOR_ACCENT);
}

pub(super) fn print_hash_hex_long(hash: &[u8; 64]) {
    let mut line1 = [0u8; 68];
    let mut line2 = [0u8; 68];
    line1[0] = b' ';
    line1[1] = b' ';
    line2[0] = b' ';
    line2[1] = b' ';

    for i in 0..32 {
        format_hex_byte(&mut line1[2 + i * 2..], hash[i]);
        format_hex_byte(&mut line2[2 + i * 2..], hash[32 + i]);
    }

    print_line(&line1[..66], COLOR_ACCENT);
    print_line(&line2[..66], COLOR_ACCENT);
}
