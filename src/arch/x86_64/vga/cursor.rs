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

use core::arch::asm;
use crate::arch::x86_64::vga::constants::*;

#[inline]
unsafe fn outb(port: u16, value: u8) { unsafe {
    asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}}

#[inline]
unsafe fn inb(port: u16) -> u8 { unsafe {
    let value: u8;
    asm!(
        "in al, dx",
        in("dx") port,
        out("al") value,
        options(nomem, nostack, preserves_flags)
    );
    value
}}

pub fn update_cursor(row: usize, col: usize) {
    if row >= SCREEN_HEIGHT || col >= SCREEN_WIDTH {
        return;
    }

    let pos = (row * SCREEN_WIDTH + col) as u16;

    // SAFETY: Writing to CRT controller ports for cursor position
    unsafe {
        outb(CRT_INDEX, CURSOR_HIGH);
        outb(CRT_DATA, (pos >> 8) as u8);
        outb(CRT_INDEX, CURSOR_LOW);
        outb(CRT_DATA, (pos & 0xFF) as u8);
    }
}

pub fn enable_cursor(start: u8, end: u8) {
    // SAFETY: Writing to CRT controller ports for cursor shape
    unsafe {
        outb(CRT_INDEX, CURSOR_START);
        let current = inb(CRT_DATA);
        outb(CRT_DATA, (current & 0xC0) | start);

        outb(CRT_INDEX, CURSOR_END);
        let current = inb(CRT_DATA);
        outb(CRT_DATA, (current & 0xE0) | end);
    }
}

pub fn disable_cursor() {
    // SAFETY: Writing to CRT controller port to disable cursor
    unsafe {
        outb(CRT_INDEX, CURSOR_START);
        outb(CRT_DATA, 0x20);
    }
}
