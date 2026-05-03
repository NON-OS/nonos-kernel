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
use crate::syscall::types::errnos::{EINVAL, ENODEV};
use crate::syscall::SyscallResult;

const PRIMARY_DISPLAY: u32 = 0;

pub fn sys_display_dimensions(display: u32) -> SyscallResult {
    if let Err(e) = require_capability(Capability::GraphicsDisplayQuery) {
        return e;
    }
    if display != PRIMARY_DISPLAY {
        return errno(EINVAL);
    }
    if !framebuffer::is_initialized() {
        return errno(ENODEV);
    }
    let (width, height) = framebuffer::dimensions();
    let packed = ((width as u64) << 32) | (height as u64);
    SyscallResult {
        value: packed as i64,
        capability_consumed: false,
        audit_required: false,
    }
}
