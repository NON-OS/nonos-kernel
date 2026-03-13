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

use core::sync::atomic::Ordering;

use super::state::{convert_color, is_initialized, FB_HEIGHT, FB_PTR, FB_STRIDE, FB_WIDTH};

#[inline]
pub fn put_pixel(x: u32, y: u32, color: u32) {
    if !is_initialized() {
        return;
    }

    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);
    let stride = FB_STRIDE.load(Ordering::Relaxed);

    if x >= width || y >= height {
        return;
    }

    let fb_ptr = FB_PTR.load(Ordering::Relaxed) as *mut u32;
    let offset = (y * stride + x) as isize;
    let native_color = convert_color(color);

    unsafe {
        fb_ptr.offset(offset).write_volatile(native_color);
    }
}

pub fn fill_rect(x: u32, y: u32, w: u32, h: u32, color: u32) {
    if !is_initialized() {
        return;
    }

    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);
    let stride = FB_STRIDE.load(Ordering::Relaxed);
    let fb_ptr = FB_PTR.load(Ordering::Relaxed) as *mut u32;
    let native_color = convert_color(color);

    for dy in 0..h {
        let py = y + dy;
        if py >= height {
            break;
        }

        for dx in 0..w {
            let px = x + dx;
            if px >= width {
                break;
            }

            let offset = (py * stride + px) as isize;
            unsafe {
                fb_ptr.offset(offset).write_volatile(native_color);
            }
        }
    }
}

pub fn hline(x: u32, y: u32, w: u32, color: u32) {
    fill_rect(x, y, w, 1, color);
}

pub fn vline(x: u32, y: u32, h: u32, color: u32) {
    fill_rect(x, y, 1, h, color);
}

pub fn draw_rect(x: u32, y: u32, w: u32, h: u32, color: u32) {
    hline(x, y, w, color);
    hline(x, y + h - 1, w, color);
    vline(x, y, h, color);
    vline(x + w - 1, y, h, color);
}

pub fn clear_screen(color: u32) {
    if !is_initialized() {
        return;
    }

    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);
    fill_rect(0, 0, width, height, color);
}
