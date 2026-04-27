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

use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::table::boot::BootServices;
use crate::handoff::types::FramebufferInfo;
use crate::display::get_cursor_y;

pub const PIXEL_FORMAT_RGB: u32 = 0;
pub const PIXEL_FORMAT_BGR: u32 = 1;
pub const PIXEL_FORMAT_BITMASK: u32 = 2;

/// Try to get framebuffer info from a GOP handle. Returns None if invalid.
pub fn try_gop_handle(bs: &BootServices, handle: Handle, _idx: usize) -> Option<FramebufferInfo> {
    let mut gop = bs.open_protocol_exclusive::<GraphicsOutput>(handle).ok()?;
    let mode_info = gop.current_mode_info();
    let (width, height) = mode_info.resolution();
    if width == 0 || height == 0 { return None; }
    let stride = mode_info.stride();
    if stride == 0 { return None; }
    let mut fb = gop.frame_buffer();
    let fb_addr = fb.as_mut_ptr() as u64;
    if fb_addr == 0 { return None; }
    let fb_size = fb.size() as u64;
    if fb_size == 0 { return None; }
    let pixel_format = match mode_info.pixel_format() {
        PixelFormat::Rgb => PIXEL_FORMAT_RGB,
        PixelFormat::Bgr => PIXEL_FORMAT_BGR,
        _ => PIXEL_FORMAT_BITMASK,
    };
    Some(FramebufferInfo { ptr: fb_addr, size: fb_size, width: width as u32, height: height as u32, stride: stride as u32, pixel_format, cursor_y: get_cursor_y(), reserved: 0 })
}
