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

use crate::boot::handoff::BootHandoffV1;
use crate::display::{register_framebuffer, FramebufferInfo};
use crate::memory::{PhysAddr, mmio};

pub(crate) fn init_framebuffer(handoff: &BootHandoffV1) {
    if handoff.fb.ptr == 0 { return; }
    let size = (handoff.fb.stride as usize) * (handoff.fb.height as usize);
    let fb_phys = PhysAddr::new(handoff.fb.ptr);
    let fb_addr = mmio::map_framebuffer(fb_phys, size)
        .map(|va| va.as_u64())
        .unwrap_or(handoff.fb.ptr);
    let info = FramebufferInfo {
        addr: fb_addr,
        width: handoff.fb.width,
        height: handoff.fb.height,
        stride: handoff.fb.stride,
        bpp: 32,
    };
    let _ = register_framebuffer(info);
    crate::graphics::framebuffer::init(fb_addr, handoff.fb.width, handoff.fb.height, handoff.fb.stride);
    let _ = crate::graphics::framebuffer::init_double_buffer();
}
