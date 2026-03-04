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

use super::state::{FB_ADDR, FB_WIDTH, FB_HEIGHT, FB_PITCH, dimensions};
use super::double_buffer;
use core::sync::atomic::Ordering;

#[inline(always)]
pub fn get_pixel(x: u32, y: u32) -> u32 {
    let addr = FB_ADDR.load(Ordering::Relaxed);
    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);
    let pitch = FB_PITCH.load(Ordering::Relaxed);

    if x >= width || y >= height || addr == 0 {
        return 0;
    }

    // SAFETY: Address and bounds validated above
    unsafe {
        let ptr = (addr as *const u32).add((y * (pitch / 4) + x) as usize);
        core::ptr::read_volatile(ptr)
    }
}

#[inline(always)]
pub fn put_pixel(x: u32, y: u32, color: u32) {
    if double_buffer::is_enabled() {
        double_buffer::put_pixel_back(x, y, color);
        return;
    }

    let addr = FB_ADDR.load(Ordering::Relaxed);
    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);
    let pitch = FB_PITCH.load(Ordering::Relaxed);

    if x >= width || y >= height || addr == 0 {
        return;
    }

    // SAFETY: Address and bounds validated above
    unsafe {
        let ptr = (addr as *mut u32).add((y * (pitch / 4) + x) as usize);
        core::ptr::write_volatile(ptr, color);
    }
}

pub fn fill_rect(x: u32, y: u32, w: u32, h: u32, color: u32) {
    if double_buffer::is_enabled() {
        double_buffer::fill_rect_back(x, y, w, h, color);
        return;
    }

    let max_x = FB_WIDTH.load(Ordering::Relaxed);
    let max_y = FB_HEIGHT.load(Ordering::Relaxed);

    for py in y..core::cmp::min(y + h, max_y) {
        for px in x..core::cmp::min(x + w, max_x) {
            put_pixel(px, py, color);
        }
    }
}

pub fn clear(color: u32) {
    if double_buffer::is_enabled() {
        double_buffer::clear_back(color);
        return;
    }
    let (w, h) = dimensions();
    fill_rect(0, 0, w, h, color);
}

pub fn hline(x: u32, y: u32, len: u32, color: u32) {
    fill_rect(x, y, len, 1, color);
}

pub fn vline(x: u32, y: u32, len: u32, color: u32) {
    fill_rect(x, y, 1, len, color);
}

pub fn draw_rect(x: u32, y: u32, w: u32, h: u32, color: u32) {
    hline(x, y, w, color);
    hline(x, y + h - 1, w, color);
    vline(x, y, h, color);
    vline(x + w - 1, y, h, color);
}

pub fn fill_rounded_rect(x: u32, y: u32, w: u32, h: u32, radius: u32, color: u32) {
    fill_rect(x + radius, y, w - 2 * radius, h, color);
    fill_rect(x, y + radius, w, h - 2 * radius, color);

    for py in 0..radius {
        for px in 0..radius {
            let dx = radius - px;
            let dy = radius - py;
            if dx * dx + dy * dy <= radius * radius {
                put_pixel(x + px, y + py, color);
                put_pixel(x + w - 1 - px, y + py, color);
                put_pixel(x + px, y + h - 1 - py, color);
                put_pixel(x + w - 1 - px, y + h - 1 - py, color);
            }
        }
    }
}
