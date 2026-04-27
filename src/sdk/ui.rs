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

use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::fill_rounded_rect;

pub trait Widget {
    fn draw(&self, x: u32, y: u32);
    fn width(&self) -> u32;
    fn height(&self) -> u32;
}

pub struct Button {
    pub text: &'static [u8],
    pub w: u32,
    pub h: u32,
    pub bg: u32,
    pub fg: u32,
}
pub struct Label {
    pub text: &'static [u8],
    pub color: u32,
}
pub struct Input {
    pub value: [u8; 64],
    pub len: u8,
    pub w: u32,
    pub focused: bool,
}
pub struct List {
    pub items: &'static [&'static [u8]],
    pub selected: usize,
    pub h: u32,
}
pub struct Panel {
    pub w: u32,
    pub h: u32,
    pub bg: u32,
    pub radius: u32,
}

impl Widget for Button {
    fn draw(&self, x: u32, y: u32) {
        fill_rounded_rect(x, y, self.w, self.h, 6, self.bg);
        let tx = x + (self.w - self.text.len() as u32 * 8) / 2;
        let ty = y + (self.h - 16) / 2;
        for (i, &c) in self.text.iter().enumerate() {
            draw_char(tx + i as u32 * 8, ty, c, self.fg);
        }
    }
    fn width(&self) -> u32 {
        self.w
    }
    fn height(&self) -> u32 {
        self.h
    }
}

impl Widget for Label {
    fn draw(&self, x: u32, y: u32) {
        for (i, &c) in self.text.iter().enumerate() {
            draw_char(x + i as u32 * 8, y, c, self.color);
        }
    }
    fn width(&self) -> u32 {
        self.text.len() as u32 * 8
    }
    fn height(&self) -> u32 {
        16
    }
}

impl Widget for Panel {
    fn draw(&self, x: u32, y: u32) {
        fill_rounded_rect(x, y, self.w, self.h, self.radius, self.bg);
    }
    fn width(&self) -> u32 {
        self.w
    }
    fn height(&self) -> u32 {
        self.h
    }
}

impl Widget for Input {
    fn draw(&self, x: u32, y: u32) {
        let bg = if self.focused { 0xFF1E1E28 } else { 0xFF16161E };
        fill_rounded_rect(x, y, self.w, 36, 6, bg);
        for i in 0..self.len as usize {
            draw_char(x + 8 + i as u32 * 8, y + 10, self.value[i], 0xFFFFFFFF);
        }
    }
    fn width(&self) -> u32 {
        self.w
    }
    fn height(&self) -> u32 {
        36
    }
}
