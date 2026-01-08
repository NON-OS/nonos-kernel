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

use super::color::{decode_color, vga_color, Color, DEFAULT_COLOR};
use super::constants::*;
use super::io;
use core::ptr;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct VgaCell {
    pub ascii: u8,
    pub color: u8,
}

impl VgaCell {
    #[inline]
    pub const fn new(ascii: u8, color: u8) -> Self {
        Self { ascii, color }
    }

    #[inline]
    pub const fn blank(color: u8) -> Self {
        Self {
            ascii: SPACE_CHAR,
            color,
        }
    }
}

pub struct Vga {
    col: usize,
    row: usize,
    color: u8,
    buf: *mut VgaCell,
    auto_cursor_update: bool,
    cursor_dirty: bool,
}

// SAFETY: VGA buffer is a fixed memory-mapped region that is safe to access
// from multiple threads as long as access is synchronized through the mutex.
unsafe impl Send for Vga {}
unsafe impl Sync for Vga {}

impl Vga {
    pub const fn new() -> Self {
        Self {
            col: 0,
            row: 0,
            color: DEFAULT_COLOR,
            buf: VGA_BUFFER_ADDR as *mut VgaCell,
            auto_cursor_update: true,
            cursor_dirty: false,
        }
    }

    #[inline]
    fn bounds_ok(row: usize, col: usize) -> bool {
        row < VGA_HEIGHT && col < VGA_WIDTH
    }

    #[inline]
    fn write_cell(&mut self, row: usize, col: usize, ch: u8, color: u8) {
        if !Self::bounds_ok(row, col) {
            return;
        }
        // SAFETY: Bounds checked above, buffer is valid VGA memory.
        unsafe {
            ptr::write_volatile(
                self.buf.add(row * VGA_WIDTH + col),
                VgaCell::new(ch, color),
            );
        }
    }

    fn mark_cursor(&mut self) {
        self.cursor_dirty = true;
        if self.auto_cursor_update {
            self.flush_cursor();
        }
    }

    pub fn flush_cursor(&mut self) {
        if !self.cursor_dirty {
            return;
        }
        let pos = (self.row * VGA_WIDTH + self.col).min(VGA_TOTAL_CELLS - 1) as u16;
        io::set_cursor_position(pos);
        self.cursor_dirty = false;
    }

    fn fast_scroll_up(&mut self) {
        // SAFETY: Buffer is valid VGA memory, copying within bounds.
        unsafe {
            let dst = self.buf as *mut u16;
            let src = self.buf.add(VGA_WIDTH) as *const u16;
            let words = (VGA_HEIGHT - 1) * VGA_WIDTH;
            ptr::copy(src, dst, words);
        }
        let blank = VgaCell::blank(self.color);
        for c in 0..VGA_WIDTH {
            // SAFETY: Writing to last row of VGA buffer.
            unsafe {
                ptr::write_volatile(self.buf.add((VGA_HEIGHT - 1) * VGA_WIDTH + c), blank);
            }
        }
        if self.row > 0 {
            self.row = VGA_HEIGHT - 1;
        }
        self.mark_cursor();
    }

    fn newline(&mut self) {
        self.col = 0;
        self.row += 1;
        if self.row >= VGA_HEIGHT {
            self.fast_scroll_up();
        } else {
            self.mark_cursor();
        }
    }

    fn put_printable(&mut self, ch: u8) {
        if self.row >= VGA_HEIGHT {
            self.fast_scroll_up();
        }
        self.write_cell(self.row, self.col, ch, self.color);
        self.col += 1;
        if self.col >= VGA_WIDTH {
            self.newline();
        } else {
            self.mark_cursor();
        }
    }

    pub fn put_char(&mut self, ch: u8) {
        match ch {
            b'\n' => self.newline(),
            b'\r' => {
                self.col = 0;
                self.mark_cursor();
            }
            BACKSPACE_CHAR => {
                if self.col > 0 {
                    self.col -= 1;
                } else if self.row > 0 {
                    self.row -= 1;
                    self.col = VGA_WIDTH - 1;
                }
                self.write_cell(self.row, self.col, SPACE_CHAR, self.color);
                self.mark_cursor();
            }
            PRINTABLE_START..=PRINTABLE_END => self.put_printable(ch),
            _ => self.put_printable(SPACE_CHAR),
        }
    }

    pub fn write_str(&mut self, s: &str) {
        for b in s.bytes() {
            self.put_char(b);
        }
    }

    pub fn write_at(&mut self, x: usize, y: usize, ch: u8) {
        if !Self::bounds_ok(y, x) {
            return;
        }
        self.write_cell(y, x, ch, self.color);
    }

    pub fn write_str_at(&mut self, x: usize, y: usize, s: &str) {
        if y >= VGA_HEIGHT {
            return;
        }
        let mut col = x.min(VGA_WIDTH);
        for b in s.bytes() {
            if col >= VGA_WIDTH {
                break;
            }
            if (PRINTABLE_START..=PRINTABLE_END).contains(&b) {
                self.write_cell(y, col, b, self.color);
            } else {
                self.write_cell(y, col, SPACE_CHAR, self.color);
            }
            col += 1;
        }
        self.mark_cursor();
    }

    pub fn clear(&mut self) {
        let blank = VgaCell::blank(self.color);
        for r in 0..VGA_HEIGHT {
            for c in 0..VGA_WIDTH {
                // SAFETY: Writing to VGA buffer within bounds.
                unsafe {
                    ptr::write_volatile(self.buf.add(r * VGA_WIDTH + c), blank);
                }
            }
        }
        self.col = 0;
        self.row = 0;
        self.mark_cursor();
    }

    pub fn clear_region(&mut self, x0: usize, y0: usize, x1_ex: usize, y1_ex: usize) {
        let blank = VgaCell::blank(self.color);
        for r in y0.min(VGA_HEIGHT)..y1_ex.min(VGA_HEIGHT) {
            for c in x0.min(VGA_WIDTH)..x1_ex.min(VGA_WIDTH) {
                // SAFETY: Writing to VGA buffer within bounds.
                unsafe {
                    ptr::write_volatile(self.buf.add(r * VGA_WIDTH + c), blank);
                }
            }
        }
        self.mark_cursor();
    }

    pub fn set_color(&mut self, fg: Color, bg: Color) {
        self.color = vga_color(fg, bg);
    }

    pub fn get_color(&self) -> (Color, Color) {
        decode_color(self.color)
    }

    pub fn set_cursor(&mut self, x: usize, y: usize) {
        self.col = x.min(VGA_WIDTH - 1);
        self.row = y.min(VGA_HEIGHT - 1);
        self.mark_cursor();
    }

    pub fn get_cursor(&self) -> (usize, usize) {
        (self.col, self.row)
    }

    pub fn set_auto_cursor_update(&mut self, on: bool) {
        self.auto_cursor_update = on;
        if on && self.cursor_dirty {
            self.flush_cursor();
        }
    }

    pub fn enable_cursor(&mut self, scanline_start: u8, scanline_end: u8) {
        io::enable_cursor(scanline_start, scanline_end);
        self.mark_cursor();
    }

    pub fn disable_cursor(&mut self) {
        io::disable_cursor();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vga_cell() {
        let cell = VgaCell::new(b'A', 0x0F);
        assert_eq!(cell.ascii, b'A');
        assert_eq!(cell.color, 0x0F);
    }

    #[test]
    fn test_vga_cell_blank() {
        let cell = VgaCell::blank(0x07);
        assert_eq!(cell.ascii, SPACE_CHAR);
        assert_eq!(cell.color, 0x07);
    }

    #[test]
    fn test_bounds_check() {
        assert!(Vga::bounds_ok(0, 0));
        assert!(Vga::bounds_ok(24, 79));
        assert!(!Vga::bounds_ok(25, 0));
        assert!(!Vga::bounds_ok(0, 80));
    }
}
