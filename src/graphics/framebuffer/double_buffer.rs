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
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::state::{FB_ADDR, FB_WIDTH, FB_HEIGHT, FB_PITCH};

static DOUBLE_BUFFER_ENABLED: AtomicBool = AtomicBool::new(false);
static BACK_BUFFER_PTR: AtomicUsize = AtomicUsize::new(0);
static BACK_BUFFER_SIZE: AtomicUsize = AtomicUsize::new(0);

static mut BACK_BUFFER: Option<Vec<u32>> = None;

pub fn init_double_buffer() -> bool {
    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);

    if width == 0 || height == 0 {
        return false;
    }

    let size = (width as usize) * (height as usize);

    // SAFETY: Only called from main thread during initialization
    unsafe {
        BACK_BUFFER = Some(alloc::vec![0u32; size]);
        if let Some(ref buf) = BACK_BUFFER {
            BACK_BUFFER_PTR.store(buf.as_ptr() as usize, Ordering::SeqCst);
            BACK_BUFFER_SIZE.store(size, Ordering::SeqCst);
            DOUBLE_BUFFER_ENABLED.store(true, Ordering::SeqCst);
            return true;
        }
    }

    false
}

pub fn is_enabled() -> bool {
    DOUBLE_BUFFER_ENABLED.load(Ordering::Relaxed)
}

pub fn enable() {
    if BACK_BUFFER_PTR.load(Ordering::Relaxed) != 0 {
        DOUBLE_BUFFER_ENABLED.store(true, Ordering::SeqCst);
    }
}

pub fn disable() {
    DOUBLE_BUFFER_ENABLED.store(false, Ordering::SeqCst);
}

pub fn get_back_buffer_ptr() -> *mut u32 {
    BACK_BUFFER_PTR.load(Ordering::Relaxed) as *mut u32
}

pub fn put_pixel_back(x: u32, y: u32, color: u32) {
    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);
    let ptr = BACK_BUFFER_PTR.load(Ordering::Relaxed) as *mut u32;

    if x >= width || y >= height || ptr.is_null() {
        return;
    }

    let offset = (y as usize) * (width as usize) + (x as usize);
    // SAFETY: Bounds checked above, back buffer is valid
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
            // SAFETY: Bounds checked in loop conditions
            unsafe {
                *ptr.add(row_start + px as usize) = color;
            }
        }
    }
}

pub fn swap_buffers() {
    if !DOUBLE_BUFFER_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    let fb_addr = FB_ADDR.load(Ordering::Relaxed);
    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);
    let pitch = FB_PITCH.load(Ordering::Relaxed);
    let back_ptr = BACK_BUFFER_PTR.load(Ordering::Relaxed) as *const u32;

    if fb_addr == 0 || back_ptr.is_null() {
        return;
    }

    let fb_ptr = fb_addr as *mut u32;
    let pixels_per_row = (pitch / 4) as usize;
    let back_width = width as usize;

    // SAFETY: Both buffers are valid and have appropriate sizes
    unsafe {
        for y in 0..height as usize {
            let fb_row = fb_ptr.add(y * pixels_per_row);
            let back_row = back_ptr.add(y * back_width);
            core::ptr::copy_nonoverlapping(back_row, fb_row, back_width);
        }
    }
}

pub fn clear_back(color: u32) {
    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);
    fill_rect_back(0, 0, width, height, color);
}
