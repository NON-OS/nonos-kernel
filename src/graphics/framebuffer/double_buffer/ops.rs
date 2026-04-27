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

use super::state::BACK_BUFFER_PTR;
use crate::graphics::framebuffer::state::{FB_HEIGHT, FB_WIDTH};
use core::sync::atomic::Ordering;

pub fn put_pixel_back(x: u32, y: u32, color: u32) {
    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);
    let ptr = BACK_BUFFER_PTR.load(Ordering::Relaxed) as *mut u32;
    if x >= width || y >= height || ptr.is_null() {
        return;
    }
    let offset = (y as usize) * (width as usize) + (x as usize);
    unsafe {
        *ptr.add(offset) = color;
    }
}

pub fn fill_rect_back(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);
    let ptr = BACK_BUFFER_PTR.load(Ordering::Relaxed) as *mut u32;
    if ptr.is_null() {
        return;
    }
    let x_end = core::cmp::min(x + w, width);
    let y_end = core::cmp::min(y + h, height);
    for py in y..y_end {
        let row_start = (py as usize) * (width as usize);
        for px in x..x_end {
            unsafe {
                *ptr.add(row_start + px as usize) = color;
            }
        }
    }
}

pub fn clear_back(color: u32) {
    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);
    fill_rect_back(0, 0, width, height, color);
}
