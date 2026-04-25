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

pub(crate) fn init_framebuffer(handoff: &BootHandoffV1) {
    use crate::sys::serial;
    if handoff.fb.ptr == 0 {
        serial::println(b"[FB] No framebuffer pointer");
        return;
    }
    serial::println(b"[FB] Initializing framebuffer");
    let fb_addr = handoff.fb.ptr;
    let info = FramebufferInfo {
        addr: fb_addr,
        width: handoff.fb.width,
        height: handoff.fb.height,
        stride: handoff.fb.stride * 4,
        bpp: 32,
    };
    if let Err(_) = register_framebuffer(info) {
        serial::println(b"[FB] register_framebuffer failed");
    }
    crate::graphics::framebuffer::init(
        fb_addr,
        handoff.fb.width,
        handoff.fb.height,
        handoff.fb.stride,
    );
    let (w, h) = crate::graphics::framebuffer::dimensions();
    if w > 0 && h > 0 {
        serial::println(b"[FB] Graphics FB ready");
    } else {
        serial::println(b"[FB] Graphics FB dimensions zero!");
    }
    let _ = crate::graphics::framebuffer::init_double_buffer();
    crate::graphics::framebuffer::clear(0x00000000);
    crate::graphics::framebuffer::swap_buffers();
}
