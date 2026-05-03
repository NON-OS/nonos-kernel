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

use crate::capabilities::Capability;
use crate::display::framebuffer;
use crate::memory::unified::phys_to_virt;
use crate::syscall::dispatch::util::{errno, require_capability};
use crate::syscall::types::errnos::{EINVAL, ENODEV};
use crate::syscall::SyscallResult;

use super::registry::{snapshot, SurfaceId};

const PAGE_SIZE: u64 = 4096;

pub fn sys_cursor_present(
    display: u32,
    id: SurfaceId,
    hot_x: u32,
    hot_y: u32,
) -> SyscallResult {
    if let Err(e) = require_capability(Capability::GraphicsPresent) {
        return e;
    }
    if display != 0 {
        return errno(EINVAL);
    }
    if !framebuffer::is_initialized() {
        return errno(ENODEV);
    }
    let Some(proc) = crate::process::current_process() else {
        return errno(EINVAL);
    };
    let Some(view) = snapshot(id, proc.pid()) else {
        return errno(EINVAL);
    };

    let bpp = view.fmt.bytes_per_pixel() as u64;
    let (fb_w, fb_h) = framebuffer::dimensions();
    if hot_x >= fb_w || hot_y >= fb_h {
        return errno(EINVAL);
    }
    let fb_addr = framebuffer::addr();
    let fb_pitch = framebuffer::pitch() as u64;
    let copy_w = view.width.min(fb_w.saturating_sub(hot_x));
    let copy_h = view.height.min(fb_h.saturating_sub(hot_y));
    let src_row_bytes = view.width as u64 * bpp;

    for row in 0..copy_h {
        for col in 0..copy_w {
            let src_byte = (row as u64) * src_row_bytes + (col as u64) * bpp;
            let frame_idx = (src_byte / PAGE_SIZE) as usize;
            let frame_off = src_byte % PAGE_SIZE;
            let src_va = phys_to_virt(view.frames[frame_idx]).as_u64() + frame_off;
            let dx = (hot_x + col) as u64;
            let dy = (hot_y + row) as u64;
            let dst = fb_addr + dy * fb_pitch + dx * bpp;
            unsafe {
                let pixel = core::ptr::read_volatile(src_va as *const u32);
                core::ptr::write_volatile(dst as *mut u32, pixel);
            }
        }
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
