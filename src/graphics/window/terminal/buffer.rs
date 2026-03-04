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

use core::sync::atomic::Ordering;
use crate::graphics::framebuffer::COLOR_TEXT_WHITE;
use super::constants::*;
use super::state::*;

pub fn put_char(ch: u8, color: u32) {
    let x = TERM_CURSOR_X.load(Ordering::Relaxed);
    let y = TERM_CURSOR_Y.load(Ordering::Relaxed);

    if x >= TERM_COLS {
        newline();
        return put_char(ch, color);
    }

    let idx = y * TERM_COLS + x;
    if idx < TERM_BUFFER_SIZE {
        // SAFETY: Bounds checked above
        unsafe {
            TERM_BUFFER[idx] = ch;
            TERM_COLORS[idx] = color;
        }
    }
    TERM_CURSOR_X.store(x + 1, Ordering::Relaxed);
}

pub fn newline() {
    TERM_CURSOR_X.store(0, Ordering::Relaxed);
    let y = TERM_CURSOR_Y.load(Ordering::Relaxed);

    if y + 1 >= TERM_ROWS {
        scroll_up();
    } else {
        TERM_CURSOR_Y.store(y + 1, Ordering::Relaxed);
    }
}

pub fn scroll_up() {
    // SAFETY: Single-threaded terminal buffer access
    unsafe {
        for y in 0..TERM_ROWS - 1 {
            for x in 0..TERM_COLS {
                let dst = y * TERM_COLS + x;
                let src = (y + 1) * TERM_COLS + x;
                TERM_BUFFER[dst] = TERM_BUFFER[src];
                TERM_COLORS[dst] = TERM_COLORS[src];
            }
        }
        let last_row = (TERM_ROWS - 1) * TERM_COLS;
        for x in 0..TERM_COLS {
            TERM_BUFFER[last_row + x] = b' ';
            TERM_COLORS[last_row + x] = COLOR_TEXT_WHITE;
        }
    }
}

pub fn clear_screen() {
    // SAFETY: Single-threaded terminal buffer access
    unsafe {
        for i in 0..TERM_BUFFER_SIZE {
            TERM_BUFFER[i] = b' ';
            TERM_COLORS[i] = COLOR_TEXT_WHITE;
        }
    }
    TERM_CURSOR_X.store(0, Ordering::Relaxed);
    TERM_CURSOR_Y.store(0, Ordering::Relaxed);
}

pub fn print_line(text: &[u8], color: u32) {
    for &ch in text {
        put_char(ch, color);
    }
    newline();
}

pub fn print_number(n: u32) {
    if n == 0 {
        put_char(b'0', COLOR_TEXT_WHITE);
        return;
    }

    let mut buf = [0u8; 10];
    let mut i = 0;
    let mut val = n;

    while val > 0 && i < 10 {
        buf[9 - i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }

    for j in (10 - i)..10 {
        put_char(buf[j], COLOR_TEXT_WHITE);
    }
}

pub fn print_hex(n: u32) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    let mut buf = [0u8; 8];
    let mut val = n;

    for i in (0..4).rev() {
        buf[i] = HEX_CHARS[(val & 0xF) as usize];
        val >>= 4;
    }

    for i in 0..4 {
        put_char(buf[i], COLOR_TEXT_WHITE);
    }
}

pub fn starts_with(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    &haystack[..needle.len()] == needle
}

pub fn trim_whitespace(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&c| c != b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|&c| c != b' ').map(|i| i + 1).unwrap_or(start);
    &s[start..end]
}
