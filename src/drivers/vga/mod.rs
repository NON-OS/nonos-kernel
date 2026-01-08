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

pub mod buffer;
pub mod color;
pub mod constants;
pub mod error;
pub mod io;

#[cfg(test)]
mod tests;

use buffer::Vga;
use spin::Mutex;

pub use buffer::VgaCell;
pub use color::{decode_color, vga_color, Color, DEFAULT_BG, DEFAULT_COLOR, DEFAULT_FG};
pub use constants::{VGA_BUFFER_ADDR, VGA_HEIGHT, VGA_TOTAL_CELLS, VGA_WIDTH};

static VGA: Mutex<Vga> = Mutex::new(Vga::new());

pub fn init_vga() {
    let mut g = VGA.lock();
    g.clear();
    g.enable_cursor(0, 15);
    g.flush_cursor();
}

pub fn clear() {
    let mut g = VGA.lock();
    g.clear();
    g.flush_cursor();
}

pub fn clear_region(x0: usize, y0: usize, x1_ex: usize, y1_ex: usize) {
    let mut g = VGA.lock();
    g.clear_region(x0, y0, x1_ex, y1_ex);
    g.flush_cursor();
}

pub fn set_color(fg: Color, bg: Color) {
    VGA.lock().set_color(fg, bg);
}

pub fn get_color() -> (Color, Color) {
    VGA.lock().get_color()
}

pub fn put_char(ch: u8) {
    let mut g = VGA.lock();
    g.put_char(ch);
    g.flush_cursor();
}

pub fn write_str(s: &str) {
    let mut g = VGA.lock();
    g.write_str(s);
    g.flush_cursor();
}

pub fn write_at(x: usize, y: usize, ch: u8) {
    let mut g = VGA.lock();
    g.write_at(x, y, ch);
    g.flush_cursor();
}

pub fn write_str_at(x: usize, y: usize, s: &str) {
    let mut g = VGA.lock();
    g.write_str_at(x, y, s);
    g.flush_cursor();
}

pub fn set_cursor(x: usize, y: usize) {
    let mut g = VGA.lock();
    g.set_cursor(x, y);
    g.flush_cursor();
}

pub fn get_cursor() -> (usize, usize) {
    VGA.lock().get_cursor()
}

pub fn enable_cursor(start: u8, end: u8) {
    let mut g = VGA.lock();
    g.enable_cursor(start, end);
    g.flush_cursor();
}

pub fn disable_cursor() {
    VGA.lock().disable_cursor();
}

pub fn set_auto_cursor_update(on: bool) {
    VGA.lock().set_auto_cursor_update(on);
}

pub fn flush_cursor() {
    VGA.lock().flush_cursor();
}

pub fn try_write_str(s: &str) {
    if let Some(mut g) = VGA.try_lock() {
        g.write_str(s);
        g.flush_cursor();
    }
}

pub fn get_size() -> (usize, usize) {
    (VGA_WIDTH, VGA_HEIGHT)
}
