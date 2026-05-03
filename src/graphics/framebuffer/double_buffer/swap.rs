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

use super::state::{BACK_BUFFER_PTR, DOUBLE_BUFFER_ENABLED};
use crate::display::framebuffer::{addr as fb_addr, dimensions, pitch as fb_pitch};
use core::sync::atomic::Ordering;

pub fn swap_buffers() {
    if !DOUBLE_BUFFER_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let fb_addr = fb_addr();
    let (width, height) = dimensions();
    let pitch = fb_pitch();
    let back_ptr = BACK_BUFFER_PTR.load(Ordering::Relaxed) as *const u32;
    if fb_addr == 0 || back_ptr.is_null() {
        return;
    }
    let fb_ptr = fb_addr as *mut u32;
    let pixels_per_row = (pitch / 4) as usize;
    let back_width = width as usize;
    unsafe {
        for y in 0..height as usize {
            let fb_row = fb_ptr.add(y * pixels_per_row);
            let back_row = back_ptr.add(y * back_width);
            core::ptr::copy_nonoverlapping(back_row, fb_row, back_width);
        }
    }
}
