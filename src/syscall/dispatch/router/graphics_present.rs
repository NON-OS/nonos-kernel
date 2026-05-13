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

use crate::syscall::SyscallResult;
use crate::usercopy::copy_from_user;
use crate::boot::handoff::pixel_format;

const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const ENOTSUP: i32 = 95;

pub(super) fn handle(display: u64, surface: u64) -> SyscallResult {
    blit(display, surface, 0, 0, 0, 0, true)
}

pub(super) fn handle_rect(
    display: u64,
    surface: u64,
    x: u64,
    y: u64,
    w: u64,
    h: u64,
) -> SyscallResult {
    blit(display, surface, x, y, w, h, false)
}

fn blit(display: u64, surface: u64, x: u64, y: u64, w: u64, h: u64, full: bool) -> SyscallResult {
    if display != 0 {
        return super::super::util::errno(EINVAL);
    }
    let span = match super::graphics_backend::surface_span_for_id(surface) {
        Ok(v) => v,
        Err(e) => return super::super::util::errno(e),
    };
    let Some(fb) = crate::kernel_core::init::framebuffer::framebuffer_state() else {
        return super::super::util::errno(ENOTSUP);
    };
    let Some(frame_len) = fb.frame_len()
    else {
        return super::super::util::errno(EINVAL);
    };
    if span < frame_len {
        return super::super::util::errno(EINVAL);
    }
    let fb_w = fb.width as usize;
    let fb_h = fb.height as usize;
    let fb_stride_bytes = fb.stride as usize;
    let rect_x = x as usize;
    let rect_y = y as usize;
    let rect_w = if full { fb_w } else { w as usize };
    let rect_h = if full { fb_h } else { h as usize };
    if rect_w == 0 || rect_h == 0 {
        return super::super::util::errno(EINVAL);
    }
    if rect_x >= fb_w || rect_y >= fb_h {
        return super::super::util::errno(EINVAL);
    }
    if rect_x.saturating_add(rect_w) > fb_w || rect_y.saturating_add(rect_h) > fb_h {
        return super::super::util::errno(EINVAL);
    }
    let mut bounce = [0u32; 256];
    let dst = (fb.base_va.as_u64() + fb.offset as u64) as *mut u8;
    let src_bpp = core::mem::size_of::<u32>();
    let dst_bpp = 4usize;
    let src_stride = fb_w * src_bpp;
    let dst_stride = fb_stride_bytes;
    let required_end = (rect_y + rect_h - 1)
        .saturating_mul(dst_stride)
        .saturating_add(rect_x.saturating_mul(dst_bpp))
        .saturating_add(rect_w.saturating_mul(dst_bpp));
    if required_end > frame_len {
        return super::super::util::errno(EINVAL);
    }
    for row in 0..rect_h {
        let src_row_off = ((rect_y + row) * src_stride) + (rect_x * src_bpp);
        let dst_row_off = ((rect_y + row) * dst_stride) + (rect_x * dst_bpp);
        let mut copied_px = 0usize;
        while copied_px < rect_w {
            let chunk_px = core::cmp::min(bounce.len(), rect_w - copied_px);
            let src = surface + (src_row_off + copied_px * src_bpp) as u64;
            let chunk_bytes = chunk_px * src_bpp;
            let dst_chunk = unsafe {
                core::slice::from_raw_parts_mut(bounce.as_mut_ptr() as *mut u8, chunk_bytes)
            };
            if copy_from_user(src, dst_chunk).is_err() {
                return super::super::util::errno(EFAULT);
            }
            let dst_off = dst_row_off + copied_px * dst_bpp;
            for i in 0..chunk_px {
                let argb = bounce[i];
                let r = ((argb >> 16) & 0xFF) as u8;
                let g = ((argb >> 8) & 0xFF) as u8;
                let b = (argb & 0xFF) as u8;
                let p = dst_off + i * dst_bpp;
                match fb.pixel_format {
                    pixel_format::RGB | pixel_format::RGBX => {
                        unsafe {
                            core::ptr::write_volatile(dst.add(p), r);
                            core::ptr::write_volatile(dst.add(p + 1), g);
                            core::ptr::write_volatile(dst.add(p + 2), b);
                            if dst_bpp == 4 {
                                core::ptr::write_volatile(dst.add(p + 3), 0);
                            }
                        }
                    }
                    _ => {
                        unsafe {
                            core::ptr::write_volatile(dst.add(p), b);
                            core::ptr::write_volatile(dst.add(p + 1), g);
                            core::ptr::write_volatile(dst.add(p + 2), r);
                            if dst_bpp == 4 {
                                core::ptr::write_volatile(dst.add(p + 3), 0);
                            }
                        }
                    }
                }
            }
            copied_px += chunk_px;
        }
    }
    SyscallResult::success_audited(0)
}
