// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! VGA text mode operations.
//!
//! Low-level VGA hardware access including cursor positioning,
//! cell writing and screen scrolling.
//!
//! # Safety
//!
//! All functions in this module that take a buffer pointer require:
//! - The buffer must point to valid VGA memory (0xB8000)
//! - The buffer must remain valid for the lifetime of the operation
//! - Row and column parameters are bounds-checked before access
//!
//! This module directly accesses:
//! - VGA text buffer at 0xB8000 (memory-mapped I/O)
//! - CRT Controller ports 0x3D4/0x3D5 (port I/O)

use core::ptr;

use super::constants::*;
use super::types::{VgaCell, Color, make_color};

// =============================================================================
// Port I/O
// =============================================================================

/// Writes a byte to an I/O port.
/// # Safety
/// This directly accesses hardware I/O ports. Only call with valid VGA ports.
#[inline(always)]
pub unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nostack, preserves_flags)
    );
}

/// Reads a byte from an I/O port.
/// # Safety
/// This directly accesses hardware I/O ports.
#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") val,
        in("dx") port,
        options(nostack, preserves_flags)
    );
    val
}

// =============================================================================
// Cursor Operations
// =============================================================================
/// Updates the hardware cursor position.
pub fn set_cursor(row: usize, col: usize) {
    let pos = ((row * VGA_WIDTH + col).min(VGA_CELLS - 1)) as u16;

    // SAFETY: Writing to VGA CRT controller ports to update cursor.
    unsafe {
        outb(VGA_CRTC_INDEX, CRTC_CURSOR_LOW);
        outb(VGA_CRTC_DATA, (pos & 0xFF) as u8);
        outb(VGA_CRTC_INDEX, CRTC_CURSOR_HIGH);
        outb(VGA_CRTC_DATA, ((pos >> 8) & 0xFF) as u8);
    }
}

/// Hides the hardware cursor by moving it off-screen.
pub fn hide_cursor() {
    set_cursor(VGA_HEIGHT, 0);
}

/// Enables the hardware cursor with specified shape.
pub fn enable_cursor(start: u8, end: u8) {
    // SAFETY: Writing to VGA CRT controller ports to configure cursor.
    unsafe {
        outb(VGA_CRTC_INDEX, CRTC_CURSOR_START);
        outb(VGA_CRTC_DATA, start & 0x1F); // Clear disable bit, set start
        outb(VGA_CRTC_INDEX, CRTC_CURSOR_END);
        outb(VGA_CRTC_DATA, end & 0x1F);
    }
}

/// Disables the hardware cursor (makes it invisible).
pub fn disable_cursor() {
    // SAFETY: Writing to VGA CRT controller ports to disable cursor.
    unsafe {
        outb(VGA_CRTC_INDEX, CRTC_CURSOR_START);
        outb(VGA_CRTC_DATA, CURSOR_DISABLE);
    }
}

/// Sets cursor to block shape (covers full character cell).
pub fn set_block_cursor() {
    enable_cursor(0, 15);
}

/// Sets cursor to underline shape (single line at bottom).
pub fn set_underline_cursor() {
    enable_cursor(13, 15);
}

// =============================================================================
// Cell Operations
// =============================================================================
/// Writes a single cell to the VGA buffer.
/// # Safety
/// Buffer must point to valid VGA memory.
#[inline]
pub unsafe fn write_cell(buffer: *mut VgaCell, row: usize, col: usize, cell: VgaCell) {
    if row < VGA_HEIGHT && col < VGA_WIDTH {
        ptr::write_volatile(buffer.add(row * VGA_WIDTH + col), cell);
    }
}

/// Writes a character with color to the VGA buffer.
/// # Safety
/// Buffer must point to valid VGA memory.
#[inline]
pub unsafe fn write_char(buffer: *mut VgaCell, row: usize, col: usize, ch: u8, color: u8) {
    write_cell(buffer, row, col, VgaCell::new(ch, color));
}

/// Reads a cell from the VGA buffer.
/// # Safety
/// Buffer must point to valid VGA memory.
#[inline]
pub unsafe fn read_cell(buffer: *const VgaCell, row: usize, col: usize) -> VgaCell {
    if row < VGA_HEIGHT && col < VGA_WIDTH {
        ptr::read_volatile(buffer.add(row * VGA_WIDTH + col))
    } else {
        VgaCell::default()
    }
}

// =============================================================================
// Screen Operations
// =============================================================================
/// # Safety
/// Buffer must point to valid VGA memory.
pub unsafe fn clear_region(
    buffer: *mut VgaCell,
    r0: usize,
    c0: usize,
    r1: usize,
    c1: usize,
    color: u8,
) {
    let blank = VgaCell::blank(color);
    let r1 = r1.min(VGA_HEIGHT);
    let c1 = c1.min(VGA_WIDTH);

    for r in r0..r1 {
        for c in c0..c1 {
            ptr::write_volatile(buffer.add(r * VGA_WIDTH + c), blank);
        }
    }
}

/// Clears the entire screen.
/// # Safety
/// Buffer must point to valid VGA memory.
pub unsafe fn clear_screen(buffer: *mut VgaCell, color: u8) {
    clear_region(buffer, 0, 0, VGA_HEIGHT, VGA_WIDTH, color);
}

/// Scrolls the screen up by one line.
/// # Safety
/// Buffer must point to valid VGA memory.
pub unsafe fn scroll_up(buffer: *mut VgaCell, color: u8) {
    // Move rows 1..N to 0..N-1 using word copies
    // Each VgaCell is 2 bytes (u16)
    let dst = buffer as *mut u16;
    let src = buffer.add(VGA_WIDTH) as *const u16;
    let words = (VGA_HEIGHT - 1) * VGA_WIDTH;
    ptr::copy(src, dst, words);

    // Clear the last row
    let blank = VgaCell::blank(color);
    for c in 0..VGA_WIDTH {
        ptr::write_volatile(buffer.add((VGA_HEIGHT - 1) * VGA_WIDTH + c), blank);
    }
}

/// Scrolls the screen down by one line.
/// Moves all rows down by one, discarding the bottom row and clearing the top.
/// # Safety
/// Buffer must point to valid VGA memory.
pub unsafe fn scroll_down(buffer: *mut VgaCell, color: u8) {
    // Move rows 0..N-1 to 1..N (must copy backwards to avoid overlap)
    for r in (1..VGA_HEIGHT).rev() {
        let dst = buffer.add(r * VGA_WIDTH);
        let src = buffer.add((r - 1) * VGA_WIDTH);
        ptr::copy(src, dst, VGA_WIDTH);
    }

    // Clear the first row
    let blank = VgaCell::blank(color);
    for c in 0..VGA_WIDTH {
        ptr::write_volatile(buffer.add(c), blank);
    }
}

// =============================================================================
// Initialization
// =============================================================================

/// Initializes the VGA text mode buffer.
/// # Safety
/// Buffer must point to valid VGA memory.
pub unsafe fn init_vga(buffer: *mut VgaCell) {
    let color = make_color(Color::LightGrey, Color::Black);
    clear_screen(buffer, color);
    set_cursor(0, 0);
}
