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
use crate::syscall::dispatch::util::{errno, require_capability};
use crate::syscall::types::errnos::{EFAULT, EINVAL, ENODEV};
use crate::syscall::SyscallResult;
use crate::usercopy::write_user_value;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DisplayInfo {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub fmt: u32,
    pub flags: u32,
}

const FMT_ARGB8888: u32 = 1;
const FLAG_PRIMARY: u32 = 1;

pub fn sys_display_list(out_buf: u64, max: u32) -> SyscallResult {
    if let Err(e) = require_capability(Capability::GraphicsDisplayQuery) {
        return e;
    }
    if !framebuffer::is_initialized() {
        return errno(ENODEV);
    }
    if max == 0 || out_buf == 0 {
        return errno(EINVAL);
    }

    let (width, height) = framebuffer::dimensions();
    let info = DisplayInfo {
        id: 0,
        width,
        height,
        pitch: framebuffer::pitch(),
        fmt: FMT_ARGB8888,
        flags: FLAG_PRIMARY,
    };

    if write_user_value(out_buf, &info).is_err() {
        return errno(EFAULT);
    }

    SyscallResult { value: 1, capability_consumed: false, audit_required: false }
}
