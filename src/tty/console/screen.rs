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

extern crate alloc;

use alloc::vec::Vec;

pub struct ScreenBuffer {
    pub rows: usize,
    pub cols: usize,
    pub buffer: Vec<ScreenCell>,
    pub attr: u8,
}

#[derive(Clone, Copy)]
pub struct ScreenCell {
    pub character: u8,
    pub attribute: u8,
}

impl Default for ScreenCell {
    fn default() -> Self {
        Self { character: b' ', attribute: 0x07 }
    }
}

impl ScreenBuffer {
    pub fn new(rows: usize, cols: usize) -> Self {
        Self { rows, cols, buffer: alloc::vec![ScreenCell::default(); rows * cols], attr: 0x07 }
    }

    pub fn put_char(&mut self, x: usize, y: usize, c: u8) {
        if x < self.cols && y < self.rows {
            let idx = y * self.cols + x;
            self.buffer[idx] = ScreenCell { character: c, attribute: self.attr };
        }
    }

    pub fn get_char(&self, x: usize, y: usize) -> ScreenCell {
        if x < self.cols && y < self.rows {
            self.buffer[y * self.cols + x]
        } else {
            ScreenCell::default()
        }
    }

    pub fn scroll_up(&mut self) {
        for y in 1..self.rows {
            for x in 0..self.cols {
                self.buffer[(y - 1) * self.cols + x] = self.buffer[y * self.cols + x];
            }
        }
        for x in 0..self.cols {
            self.buffer[(self.rows - 1) * self.cols + x] = ScreenCell::default();
        }
    }

    pub fn scroll_down(&mut self) {
        for y in (0..self.rows - 1).rev() {
            for x in 0..self.cols {
                self.buffer[(y + 1) * self.cols + x] = self.buffer[y * self.cols + x];
            }
        }
        for x in 0..self.cols {
            self.buffer[x] = ScreenCell::default();
        }
    }

    pub fn clear(&mut self) {
        for cell in self.buffer.iter_mut() {
            *cell = ScreenCell::default();
        }
    }

    pub fn flush_to_display(&self) {
        let vga = 0xB8000 as *mut u16;
        for (i, cell) in self.buffer.iter().enumerate() {
            unsafe {
                vga.add(i).write_volatile((cell.attribute as u16) << 8 | cell.character as u16);
            }
        }
    }

    pub fn set_attribute(&mut self, attr: u8) {
        self.attr = attr;
    }
}

pub fn clear_screen() {
    if let Some(vt) = super::get_active_vt() {
        vt.screen.lock().clear();
    }
}
pub fn scroll_up() {
    if let Some(vt) = super::get_active_vt() {
        vt.screen.lock().scroll_up();
    }
}
pub fn scroll_down() {
    if let Some(vt) = super::get_active_vt() {
        vt.screen.lock().scroll_down();
    }
}
