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

use super::state::Framebuffer;
use crate::display::error::DisplayError;

pub fn write_pixel(x: u32, y: u32, color: u32) -> Result<(), DisplayError> {
    let info = Framebuffer::info()?;
    if x >= info.width || y >= info.height {
        return Err(DisplayError::OutOfBounds);
    }
    let offset = (y as u64) * (info.stride as u64) + (x as u64) * (info.bpp as u64 / 8);
    let ptr = (info.addr + offset) as *mut u32;
    unsafe {
        core::ptr::write_volatile(ptr, color);
    }
    Ok(())
}

pub fn fill_rect(x: u32, y: u32, w: u32, h: u32, color: u32) -> Result<(), DisplayError> {
    let info = Framebuffer::info()?;
    let x_end = x.saturating_add(w).min(info.width);
    let y_end = y.saturating_add(h).min(info.height);
    for py in y..y_end {
        for px in x..x_end {
            let offset = (py as u64) * (info.stride as u64) + (px as u64) * 4;
            let ptr = (info.addr + offset) as *mut u32;
            unsafe {
                core::ptr::write_volatile(ptr, color);
            }
        }
    }
    Ok(())
}

pub fn clear(color: u32) -> Result<(), DisplayError> {
    let info = Framebuffer::info()?;
    fill_rect(0, 0, info.width, info.height, color)
}
