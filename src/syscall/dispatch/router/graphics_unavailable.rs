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

//! Graphics numbers park here and return ENOTSUP until a backend lands.

use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;
use crate::usercopy::write_user_value;

const ENOTSUP: i32 = 95;
const EFAULT: i32 = 14;
const EINVAL: i32 = 22;

pub(super) fn matches(nr: SyscallNumber) -> bool {
    matches!(
        nr,
        SyscallNumber::GraphicsDisplayDimensions
            | SyscallNumber::GraphicsSurfaceCreate
            | SyscallNumber::GraphicsSurfaceDestroy
            | SyscallNumber::GraphicsSurfaceMap
            | SyscallNumber::GraphicsSurfacePresentFull
            | SyscallNumber::GraphicsSurfacePresentRect
            | SyscallNumber::GraphicsDisplayList
            | SyscallNumber::GraphicsCursorPresent
    )
}

pub(super) fn handle(nr: SyscallNumber, display: u64, out_w: u64, out_h: u64) -> SyscallResult {
    match nr {
        SyscallNumber::GraphicsDisplayDimensions => handle_display_dimensions(display, out_w, out_h),
        _ => super::super::util::errno(ENOTSUP),
    }
}

fn handle_display_dimensions(display: u64, out_w: u64, out_h: u64) -> SyscallResult {
    if display != 0 || out_w == 0 || out_h == 0 {
        return super::super::util::errno(EINVAL);
    }
    let Some(handoff) = crate::boot::handoff::get_handoff() else {
        return super::super::util::errno(ENOTSUP);
    };
    let Some(fb) = handoff.framebuffer() else {
        return super::super::util::errno(ENOTSUP);
    };
    if write_user_value(out_w, &fb.width).is_err() {
        return super::super::util::errno(EFAULT);
    }
    if write_user_value(out_h, &fb.height).is_err() {
        return super::super::util::errno(EFAULT);
    }
    SyscallResult::success_audited(0)
}
