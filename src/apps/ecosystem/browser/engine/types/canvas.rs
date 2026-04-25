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

use super::image::ImageData;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct CanvasContext2D {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u32>,
    pub fill_color: u32,
    pub stroke_color: u32,
}

impl CanvasContext2D {
    pub fn new(width: u32, height: u32) -> Self {
        let pixels = alloc::vec![0x00000000; (width as usize) * (height as usize)];
        Self { width, height, pixels, fill_color: 0xFF000000, stroke_color: 0xFF000000 }
    }

    pub fn set_fill_color(&mut self, color: u32) {
        self.fill_color = color;
    }
    pub fn set_stroke_color(&mut self, color: u32) {
        self.stroke_color = color;
    }

    pub fn fill_rect(&mut self, x: i32, y: i32, w: u32, h: u32) {
        let (x0, y0) = (x.max(0) as u32, y.max(0) as u32);
        let (x1, y1) = (
            ((x as i64 + w as i64) as u32).min(self.width),
            ((y as i64 + h as i64) as u32).min(self.height),
        );
        for py in y0..y1 {
            for px in x0..x1 {
                self.pixels[(py * self.width + px) as usize] = self.fill_color;
            }
        }
    }

    pub fn stroke_rect(&mut self, x: i32, y: i32, w: u32, h: u32) {
        let (x0, y0) = (x.max(0) as u32, y.max(0) as u32);
        let (x1, y1) = (
            ((x as i64 + w as i64) as u32).min(self.width),
            ((y as i64 + h as i64) as u32).min(self.height),
        );
        for px in x0..x1 {
            if y0 < self.height {
                self.pixels[(y0 * self.width + px) as usize] = self.stroke_color;
            }
            if y1 > 0 && y1 - 1 < self.height {
                self.pixels[((y1 - 1) * self.width + px) as usize] = self.stroke_color;
            }
        }
        for py in y0..y1 {
            if x0 < self.width {
                self.pixels[(py * self.width + x0) as usize] = self.stroke_color;
            }
            if x1 > 0 && x1 - 1 < self.width {
                self.pixels[(py * self.width + x1 - 1) as usize] = self.stroke_color;
            }
        }
    }

    pub fn clear_rect(&mut self, x: i32, y: i32, w: u32, h: u32) {
        let (x0, y0) = (x.max(0) as u32, y.max(0) as u32);
        let (x1, y1) = (
            ((x as i64 + w as i64) as u32).min(self.width),
            ((y as i64 + h as i64) as u32).min(self.height),
        );
        for py in y0..y1 {
            for px in x0..x1 {
                self.pixels[(py * self.width + px) as usize] = 0x00000000;
            }
        }
    }

    pub fn fill_text(&mut self, text: &str, x: u32, y: u32) {
        let (char_w, char_h): (u32, u32) = (8, 16);
        let mut cx = x;
        for _ch in text.chars() {
            if cx + char_w > self.width || y + char_h > self.height {
                break;
            }
            for py in y..y + char_h {
                for px in cx..cx + char_w {
                    self.pixels[(py * self.width + px) as usize] = self.fill_color;
                }
            }
            cx += char_w;
        }
    }

    pub fn to_image_data(&self) -> ImageData {
        ImageData { width: self.width, height: self.height, pixels: self.pixels.clone() }
    }
}
