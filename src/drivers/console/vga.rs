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

//! VGA text mode operations.

use core::ptr;

use super::constants::*;
use super::types::{VgaCell, Color, make_color};

#[inline(always)]
pub(super) unsafe fn outb(port: u16, val: u8) { unsafe {
    // SAFETY: Caller ensures valid VGA port.
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nostack, preserves_flags)
    );
}}

pub(super) fn set_cursor(row: usize, col: usize) {
    let pos = ((row * VGA_WIDTH + col).min(VGA_CELLS - 1)) as u16;

    // SAFETY: Writing to VGA CRT controller ports to update cursor.
    unsafe {
        outb(VGA_CRTC_INDEX, CRTC_CURSOR_LOW);
        outb(VGA_CRTC_DATA, (pos & 0xFF) as u8);
        outb(VGA_CRTC_INDEX, CRTC_CURSOR_HIGH);
        outb(VGA_CRTC_DATA, ((pos >> 8) & 0xFF) as u8);
    }
}

pub(super) fn hide_cursor() {
    set_cursor(VGA_HEIGHT, 0);
}

#[inline]
pub(super) unsafe fn write_cell(buffer: *mut VgaCell, row: usize, col: usize, cell: VgaCell) { unsafe {
    // SAFETY: Caller ensures buffer points to valid VGA memory.
    if row < VGA_HEIGHT && col < VGA_WIDTH {
        ptr::write_volatile(buffer.add(row * VGA_WIDTH + col), cell);
    }
}}

#[inline]
pub(super) unsafe fn write_char(buffer: *mut VgaCell, row: usize, col: usize, ch: u8, color: u8) { unsafe {
    // SAFETY: Caller ensures buffer points to valid VGA memory.
    write_cell(buffer, row, col, VgaCell::new(ch, color));
}}

#[inline]
pub(super) unsafe fn read_cell(buffer: *const VgaCell, row: usize, col: usize) -> VgaCell { unsafe {
    // SAFETY: Caller ensures buffer points to valid VGA memory.
    if row < VGA_HEIGHT && col < VGA_WIDTH {
        ptr::read_volatile(buffer.add(row * VGA_WIDTH + col))
    } else {
        VgaCell::default()
    }
}}

pub(super) unsafe fn clear_region(
    buffer: *mut VgaCell,
    r0: usize,
    c0: usize,
    r1: usize,
    c1: usize,
    color: u8,
) { unsafe {
    // SAFETY: Caller ensures buffer points to valid VGA memory.
    let blank = VgaCell::blank(color);
    let r1 = r1.min(VGA_HEIGHT);
    let c1 = c1.min(VGA_WIDTH);

    for r in r0..r1 {
        for c in c0..c1 {
            ptr::write_volatile(buffer.add(r * VGA_WIDTH + c), blank);
        }
    }
}}

pub(super) unsafe fn clear_screen(buffer: *mut VgaCell, color: u8) { unsafe {
    // SAFETY: Caller ensures buffer points to valid VGA memory.
    clear_region(buffer, 0, 0, VGA_HEIGHT, VGA_WIDTH, color);
}}

pub(super) unsafe fn scroll_up(buffer: *mut VgaCell, color: u8) { unsafe {
    // SAFETY: Caller ensures buffer points to valid VGA memory.
    let dst = buffer as *mut u16;
    let src = buffer.add(VGA_WIDTH) as *const u16;
    let words = (VGA_HEIGHT - 1) * VGA_WIDTH;
    ptr::copy(src, dst, words);

    let blank = VgaCell::blank(color);
    for c in 0..VGA_WIDTH {
        ptr::write_volatile(buffer.add((VGA_HEIGHT - 1) * VGA_WIDTH + c), blank);
    }
}}

pub(super) unsafe fn init_vga(buffer: *mut VgaCell) { unsafe {
    // SAFETY: Caller ensures buffer points to valid VGA memory.
    let color = make_color(Color::LightGrey, Color::Black);
    clear_screen(buffer, color);
    set_cursor(0, 0);
}}
