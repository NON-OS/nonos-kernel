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
//! Console writer

use super::constants::*;
use super::types::{Color, VgaCell, make_color};
use super::vga;
use super::ansi::{AnsiParser, AnsiAction, apply_sgr};

// =============================================================================
// Console State
// =============================================================================

pub(super) struct Console {
    /// Current column (0-79).
    col: usize,
    /// Current row (0-24).
    row: usize,
    /// Saved column for cursor restore.
    saved_col: usize,
    /// Saved row for cursor restore.
    saved_row: usize,
    /// Current color attribute byte.
    color: u8,
    /// Pointer to VGA buffer.
    buf: *mut VgaCell,
    /// ANSI escape sequence parser.
    parser: AnsiParser,
    /// Whether cursor position needs updating.
    cursor_dirty: bool,
    /// Whether cursor is visible.
    cursor_visible: bool,
}

// SAFETY: Console VGA buffer access is synchronized through mutex.
// The buffer pointer is to memory-mapped hardware at a fixed address.
unsafe impl Send for Console {}
unsafe impl Sync for Console {}

impl Console {
    /// Creates a new console in the initial state.
    pub const fn new() -> Self {
        Self {
            col: 0,
            row: 0,
            saved_col: 0,
            saved_row: 0,
            color: DEFAULT_COLOR,
            buf: VGA_BUFFER_ADDR as *mut VgaCell,
            parser: AnsiParser::new(),
            cursor_dirty: false,
            cursor_visible: true,
        }
    }

    /// Flushes pending cursor position to hardware.
    pub fn flush_cursor(&mut self) {
        if self.cursor_dirty && self.cursor_visible {
            vga::set_cursor(self.row, self.col);
            self.cursor_dirty = false;
        }
    }

    /// Saves the current cursor position.
    fn save_cursor(&mut self) {
        self.saved_col = self.col;
        self.saved_row = self.row;
    }

    /// Restores the saved cursor position.
    fn restore_cursor(&mut self) {
        self.col = self.saved_col;
        self.row = self.saved_row;
        self.mark_cursor();
    }

    /// Shows the hardware cursor.
    fn show_cursor(&mut self) {
        self.cursor_visible = true;
        vga::set_cursor(self.row, self.col);
    }

    /// Hides the hardware cursor.
    fn hide_cursor(&mut self) {
        self.cursor_visible = false;
        vga::hide_cursor();
    }

    /// Marks cursor position as needing update.
    #[inline]
    fn mark_cursor(&mut self) {
        self.cursor_dirty = true;
    }

    /// Writes a character cell at the specified position.
    #[inline]
    fn write_cell(&mut self, row: usize, col: usize, ch: u8, color: u8) {
        // SAFETY: Buffer points to VGA memory, bounds checked in vga::write_char.
        unsafe {
            vga::write_char(self.buf, row, col, ch, color);
        }
    }

    /// Clears a rectangular region of the screen.
    fn clear_region(&mut self, r0: usize, c0: usize, r1: usize, c1: usize) {
        // SAFETY: Buffer points to VGA memory, bounds checked in vga::clear_region.
        unsafe {
            vga::clear_region(self.buf, r0, c0, r1, c1, self.color);
        }
    }

    /// Clears the entire screen and resets cursor to home.
    fn clear_screen(&mut self) {
        // SAFETY: Buffer points to VGA memory.
        unsafe {
            vga::clear_screen(self.buf, self.color);
        }
        self.col = 0;
        self.row = 0;
        self.mark_cursor();
    }

    /// Scrolls screen up by one line.
    ///
    /// After scrolling, the cursor remains on the last visible row.
    fn scroll_up(&mut self) {
        // SAFETY: Buffer points to VGA memory.
        unsafe {
            vga::scroll_up(self.buf, self.color);
        }
        // After scrolling up, cursor should be on the last row
        self.row = VGA_HEIGHT - 1;
        self.mark_cursor();
    }

    /// Performs a visual bell by briefly inverting screen colors.
    ///
    /// This provides visual feedback for the ASCII BEL character (0x07)
    /// without requiring PC speaker hardware. The effect inverts the
    /// first character on the display and then restores it.
    fn visual_bell(&mut self) {
        // SAFETY: Buffer points to VGA memory, we read and write within bounds.
        unsafe {
            // Invert first character on screen to create visual flash effect
            let cell = vga::read_cell(self.buf, 0, 0);
            let inverted_color = !cell.color;
            vga::write_char(self.buf, 0, 0, cell.ascii, inverted_color);

            // Small spin delay for visibility
            for _ in 0..10000 {
                core::hint::spin_loop();
            }

            // Restore original
            vga::write_char(self.buf, 0, 0, cell.ascii, cell.color);
        }
    }

    /// Advances to the next line.
    fn new_line(&mut self) {
        self.col = 0;
        self.row += 1;
        if self.row >= VGA_HEIGHT {
            self.scroll_up();
        }
        self.mark_cursor();
    }

    /// Writes a printable character at the current position.
    fn put_printable(&mut self, ch: u8) {
        if self.row >= VGA_HEIGHT {
            self.scroll_up();
        }
        self.write_cell(self.row, self.col, ch, self.color);
        self.col += 1;
        if self.col >= VGA_WIDTH {
            self.new_line();
        } else {
            self.mark_cursor();
        }
    }

    /// Processes a single byte through the console.
    ///
    /// Handles ANSI escape sequences and control characters.
    pub fn put_byte(&mut self, byte: u8) {
        match self.parser.process(byte) {
            Some(AnsiAction::Print(ch)) => {
                match ch {
                    ASCII_NEWLINE => self.new_line(),
                    ASCII_CR => {
                        self.col = 0;
                        self.mark_cursor();
                    }
                    ASCII_TAB => {
                        // Expand tab to next tab stop
                        let next = next_tab_stop(self.col).min(VGA_WIDTH - 1);
                        while self.col < next {
                            self.put_printable(b' ');
                        }
                    }
                    ASCII_BACKSPACE => {
                        if self.col > 0 {
                            self.col -= 1;
                            self.write_cell(self.row, self.col, b' ', self.color);
                            self.mark_cursor();
                        }
                    }
                    ASCII_BELL => {
                        // Visual bell: briefly invert first character to indicate bell
                        // PC speaker beep not implemented as it requires PIT channel 2
                        // and port 0x61 control which is outside console driver scope
                        self.visual_bell();
                    }
                    ASCII_FORM_FEED => {
                        // Form feed - clear screen
                        self.clear_screen();
                    }
                    ASCII_SPACE..=ASCII_TILDE => self.put_printable(ch),
                    _ => self.put_printable(b' '), // Replace non-printable
                }
            }
            Some(AnsiAction::Sgr(p1, p2)) => {
                self.color = apply_sgr(self.color, p1);
                if let Some(p) = p2 {
                    self.color = apply_sgr(self.color, p);
                }
            }
            Some(AnsiAction::CursorPosition(row, col)) => {
                self.row = row.min(VGA_HEIGHT - 1);
                self.col = col.min(VGA_WIDTH - 1);
                self.mark_cursor();
            }
            Some(AnsiAction::EraseDisplay(mode)) => {
                match mode {
                    0 => {
                        // Erase from cursor to end of screen
                        self.clear_region(self.row, self.col, self.row + 1, VGA_WIDTH);
                        self.clear_region(self.row + 1, 0, VGA_HEIGHT, VGA_WIDTH);
                    }
                    1 => {
                        // Erase from start to cursor
                        self.clear_region(0, 0, self.row, VGA_WIDTH);
                        self.clear_region(self.row, 0, self.row + 1, self.col + 1);
                    }
                    2 | 3 => {
                        // Erase entire screen
                        self.clear_screen();
                    }
                    _ => {}
                }
            }
            Some(AnsiAction::EraseLine(mode)) => {
                match mode {
                    0 => {
                        // Erase from cursor to end of line
                        self.clear_region(self.row, self.col, self.row + 1, VGA_WIDTH);
                    }
                    1 => {
                        // Erase from start of line to cursor
                        self.clear_region(self.row, 0, self.row + 1, self.col + 1);
                    }
                    2 => {
                        // Erase entire line
                        self.clear_region(self.row, 0, self.row + 1, VGA_WIDTH);
                    }
                    _ => {}
                }
            }
            Some(AnsiAction::CursorUp(n)) => {
                self.row = self.row.saturating_sub(n);
                self.mark_cursor();
            }
            Some(AnsiAction::CursorDown(n)) => {
                self.row = (self.row + n).min(VGA_HEIGHT - 1);
                self.mark_cursor();
            }
            Some(AnsiAction::CursorForward(n)) => {
                self.col = (self.col + n).min(VGA_WIDTH - 1);
                self.mark_cursor();
            }
            Some(AnsiAction::CursorBack(n)) => {
                self.col = self.col.saturating_sub(n);
                self.mark_cursor();
            }
            Some(AnsiAction::SaveCursor) => {
                self.save_cursor();
            }
            Some(AnsiAction::RestoreCursor) => {
                self.restore_cursor();
            }
            Some(AnsiAction::ShowCursor) => {
                self.show_cursor();
            }
            Some(AnsiAction::HideCursor) => {
                self.hide_cursor();
            }
            None => {
                // Sequence in progress, nothing to do
            }
        }
    }

    /// Writes a string to the console.
    pub fn write_str(&mut self, s: &str) {
        for b in s.bytes() {
            self.put_byte(b);
        }
        self.flush_cursor();
    }

    /// Clears the screen and flushes cursor.
    pub fn clear(&mut self) {
        self.clear_screen();
        self.flush_cursor();
    }

    /// Sets the current foreground and background colors.
    pub fn set_color(&mut self, fg: Color, bg: Color) {
        self.color = make_color(fg, bg);
    }
}
