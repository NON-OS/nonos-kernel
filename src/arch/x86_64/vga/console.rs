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

use core::ptr;
use crate::arch::x86_64::vga::constants::*;

pub struct Console {
    pub(crate) row: usize,
    pub(crate) col: usize,
    color: ColorCode,
    buffer: [[ScreenChar; SCREEN_WIDTH]; SCREEN_HEIGHT],
    history: [[ScreenChar; SCREEN_WIDTH]; SCROLLBACK_LINES],
    history_pos: usize,
    chars_written: u64,
}

impl Console {
    pub const fn new() -> Self {
        Self {
            row: 0,
            col: 0,
            color: ColorCode::new(Color::LightGray, Color::Black),
            buffer: [[ScreenChar::new(b' ', ColorCode::new(Color::LightGray, Color::Black)); SCREEN_WIDTH]; SCREEN_HEIGHT],
            history: [[ScreenChar::new(b' ', ColorCode::new(Color::LightGray, Color::Black)); SCREEN_WIDTH]; SCROLLBACK_LINES],
            history_pos: 0,
            chars_written: 0,
        }
    }

    pub fn clear(&mut self) {
        let blank = ScreenChar::blank(self.color);
        for row in 0..SCREEN_HEIGHT {
            for col in 0..SCREEN_WIDTH {
                self.buffer[row][col] = blank;
            }
        }
        self.row = 0;
        self.col = 0;
    }

    pub fn set_color(&mut self, fg: Color, bg: Color) {
        self.color = ColorCode::new(fg, bg);
    }

    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.newline(),
            b'\r' => self.col = 0,
            b'\t' => {
                let spaces = 4 - (self.col % 4);
                for _ in 0..spaces {
                    self.write_byte(b' ');
                }
            }
            0x08 => {
                // Backspace
                if self.col > 0 {
                    self.col -= 1;
                    self.buffer[self.row][self.col] = ScreenChar::blank(self.color);
                }
            }
            byte => {
                if self.col >= SCREEN_WIDTH {
                    self.newline();
                }

                let sc = ScreenChar::new(byte, self.color);
                self.buffer[self.row][self.col] = sc;
                self.col += 1;
                self.chars_written += 1;
            }
        }
    }

    fn newline(&mut self) {
        self.history[self.history_pos] = self.buffer[self.row];
        self.history_pos = (self.history_pos + 1) % SCROLLBACK_LINES;

        if self.row + 1 >= SCREEN_HEIGHT {
            self.scroll_up();
        } else {
            self.row += 1;
        }
        self.col = 0;
    }

    fn scroll_up(&mut self) {
        for row in 1..SCREEN_HEIGHT {
            self.buffer[row - 1] = self.buffer[row];
        }
        let blank = ScreenChar::blank(self.color);
        for col in 0..SCREEN_WIDTH {
            self.buffer[SCREEN_HEIGHT - 1][col] = blank;
        }
    }

    pub fn flush_to_vga(&self) {
        // SAFETY: VGA buffer at 0xB8000 is valid during VGA mode operation
        unsafe {
            let vga = VGA_BUFFER_ADDR as *mut u16;
            for row in 0..SCREEN_HEIGHT {
                for col in 0..SCREEN_WIDTH {
                    let offset = row * SCREEN_WIDTH + col;
                    ptr::write_volatile(vga.add(offset), self.buffer[row][col].as_u16());
                }
            }
        }
    }
}
