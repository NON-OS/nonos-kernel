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

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use uefi::prelude::*;
use uefi::proto::console::gop::GraphicsOutput;

static FB_INITIALIZED: AtomicBool = AtomicBool::new(false);
static FB_PTR: AtomicU64 = AtomicU64::new(0);
static FB_WIDTH: AtomicU32 = AtomicU32::new(0);
static FB_HEIGHT: AtomicU32 = AtomicU32::new(0);
static FB_STRIDE: AtomicU32 = AtomicU32::new(0);
static FB_FORMAT_BGR: AtomicBool = AtomicBool::new(true);

pub fn init_gop(st: &mut SystemTable<Boot>) -> bool {
    let bs = st.boot_services();

    if let Ok(gop_handle) = bs.get_handle_for_protocol::<GraphicsOutput>() {
        if let Ok(mut gop) = bs.open_protocol_exclusive::<GraphicsOutput>(gop_handle) {
            let mode_info = gop.current_mode_info();
            let (width, height) = mode_info.resolution();
            let stride = mode_info.stride();

            let mut frame_buffer = gop.frame_buffer();
            let fb_addr = frame_buffer.as_mut_ptr() as u64;

            let is_bgr = matches!(
                mode_info.pixel_format(),
                uefi::proto::console::gop::PixelFormat::Bgr
            );

            FB_PTR.store(fb_addr, Ordering::SeqCst);
            FB_WIDTH.store(width as u32, Ordering::SeqCst);
            FB_HEIGHT.store(height as u32, Ordering::SeqCst);
            FB_STRIDE.store(stride as u32, Ordering::SeqCst);
            FB_FORMAT_BGR.store(is_bgr, Ordering::SeqCst);
            FB_INITIALIZED.store(true, Ordering::SeqCst);

            return true;
        }
    }

    false
}

#[inline]
fn convert_color(argb: u32) -> u32 {
    if FB_FORMAT_BGR.load(Ordering::Relaxed) {
        argb
    } else {
        let a = (argb >> 24) & 0xFF;
        let r = (argb >> 16) & 0xFF;
        let g = (argb >> 8) & 0xFF;
        let b = argb & 0xFF;
        (a << 24) | (b << 16) | (g << 8) | r
    }
}

#[inline]
pub fn is_initialized() -> bool {
    FB_INITIALIZED.load(Ordering::Relaxed)
}

#[inline]
pub fn get_dimensions() -> (u32, u32) {
    (
        FB_WIDTH.load(Ordering::Relaxed),
        FB_HEIGHT.load(Ordering::Relaxed),
    )
}

#[inline]
pub fn get_stride() -> u32 {
    FB_STRIDE.load(Ordering::Relaxed)
}

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

    // ## SAFETY: Bounds checked above, fb_ptr points to valid framebuffer memory
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
            // ## SAFETY: Bounds checked above
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
