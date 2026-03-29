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
    if handoff.fb.ptr != 0 {
        let info = FramebufferInfo {
            addr: handoff.fb.ptr,
            width: handoff.fb.width,
            height: handoff.fb.height,
            stride: handoff.fb.stride,
            bpp: 32,
        };
        let _ = register_framebuffer(info);
    }
}
