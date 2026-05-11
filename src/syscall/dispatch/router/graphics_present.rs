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

use crate::memory::addr::PhysAddr;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_from_user;

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
    let Some(handoff) = crate::boot::handoff::get_handoff() else {
        return super::super::util::errno(ENOTSUP);
    };
    let Some(fb) = handoff.framebuffer() else {
        return super::super::util::errno(ENOTSUP);
    };
    let Some(frame_len) = (fb.width as usize)
        .checked_mul(fb.height as usize)
        .and_then(|px| px.checked_mul(core::mem::size_of::<u32>()))
    else {
        return super::super::util::errno(EINVAL);
    };
    if span < frame_len {
        return super::super::util::errno(EINVAL);
    }
    let fb_w = fb.width as usize;
    let fb_h = fb.height as usize;
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
    let base = fb.ptr & !0xFFF;
    let offset = (fb.ptr - base) as usize;
    let fb_size = core::cmp::max(fb.size as usize, frame_len);
    let Some(map_len) = offset.checked_add(fb_size) else {
        return super::super::util::errno(EINVAL);
    };
    let fb_va = match crate::memory::mmio::map_framebuffer(PhysAddr::new(base), map_len) {
        Ok(v) => v,
        Err(_) => return super::super::util::errno(ENOTSUP),
    };
    let mut bounce = [0u8; 4096];
    let dst = (fb_va.as_u64() + offset as u64) as *mut u8;
    let row_bytes = rect_w * core::mem::size_of::<u32>();
    let stride = fb_w * core::mem::size_of::<u32>();
    for row in 0..rect_h {
        let src_off = ((rect_y + row) * stride) + (rect_x * core::mem::size_of::<u32>());
        let mut copied = 0usize;
        while copied < row_bytes {
            let chunk = core::cmp::min(bounce.len(), row_bytes - copied);
            let src = surface + (src_off + copied) as u64;
            if copy_from_user(src, &mut bounce[..chunk]).is_err() {
                let _ = crate::memory::mmio::unmap_mmio(fb_va);
                return super::super::util::errno(EFAULT);
            }
            let dst_off = src_off + copied;
            for i in 0..chunk {
                unsafe { core::ptr::write_volatile(dst.add(dst_off + i), bounce[i]) };
            }
            copied += chunk;
        }
    }
    let _ = crate::memory::mmio::unmap_mmio(fb_va);
    SyscallResult::success_audited(0)
}
