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

use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct DecodedImage {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u32>,
}

impl DecodedImage {
    pub fn new(width: u32, height: u32, pixels: Vec<u32>) -> Self {
        Self { width, height, pixels }
    }

    pub fn get_pixel(&self, x: u32, y: u32) -> Option<u32> {
        if x >= self.width || y >= self.height {
            return None;
        }
        self.pixels.get((y * self.width + x) as usize).copied()
    }

    pub fn draw_at(&self, dst_x: u32, dst_y: u32) {
        use crate::graphics::framebuffer::put_pixel;

        for y in 0..self.height {
            for x in 0..self.width {
                if let Some(color) = self.get_pixel(x, y) {
                    let alpha = (color >> 24) & 0xFF;
                    if alpha > 128 {
                        put_pixel(dst_x + x, dst_y + y, color | 0xFF000000);
                    }
                }
            }
        }
    }

    pub fn draw_scaled(&self, dst_x: u32, dst_y: u32, dst_width: u32, dst_height: u32) {
        use crate::graphics::framebuffer::put_pixel;

        for dy in 0..dst_height {
            for dx in 0..dst_width {
                let sx = (dx * self.width) / dst_width;
                let sy = (dy * self.height) / dst_height;
                if let Some(color) = self.get_pixel(sx, sy) {
                    let alpha = (color >> 24) & 0xFF;
                    if alpha > 128 {
                        put_pixel(dst_x + dx, dst_y + dy, color | 0xFF000000);
                    }
                }
            }
        }
    }
}
