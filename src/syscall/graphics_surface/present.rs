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

pub fn sys_surface_present_full(display: u32, id: SurfaceId) -> SyscallResult {
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
    let fb_addr = framebuffer::addr();
    let fb_pitch = framebuffer::pitch() as u64;
    let copy_w = view.width.min(fb_w);
    let copy_h = view.height.min(fb_h);
    let src_row_bytes = view.width as u64 * bpp;

    for y in 0..copy_h {
        for x in 0..copy_w {
            let src_byte = (y as u64) * src_row_bytes + (x as u64) * bpp;
            let frame_idx = (src_byte / PAGE_SIZE) as usize;
            let frame_off = src_byte % PAGE_SIZE;
            let src_va = phys_to_virt(view.frames[frame_idx]).as_u64() + frame_off;
            let dst = fb_addr + (y as u64) * fb_pitch + (x as u64) * bpp;
            unsafe {
                let pixel = core::ptr::read_volatile(src_va as *const u32);
                core::ptr::write_volatile(dst as *mut u32, pixel);
            }
        }
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
