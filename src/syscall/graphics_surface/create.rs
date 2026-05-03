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

extern crate alloc;

use alloc::vec::Vec;

use crate::capabilities::Capability;
use crate::memory::frame_alloc::{allocate_frame, deallocate_frame};
use crate::memory::PhysAddr;
use crate::syscall::dispatch::util::{errno, require_capability};
use crate::syscall::types::errnos::{EINVAL, ENOMEM};
use crate::syscall::SyscallResult;

use super::pixel_format::PixelFmt;
use super::registry::{insert, Surface};

const PAGE_SIZE: u32 = 4096;
const MAX_DIMENSION: u32 = 4096;

pub fn sys_surface_create(width: u32, height: u32, fmt_raw: u32) -> SyscallResult {
    if let Err(e) = require_capability(Capability::GraphicsSurfaceCreate) {
        return e;
    }
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
        return errno(EINVAL);
    }
    let Some(fmt) = PixelFmt::from_raw(fmt_raw) else {
        return errno(EINVAL);
    };
    let Some(proc) = crate::process::current_process() else {
        return errno(EINVAL);
    };
    let Some(byte_size) = width
        .checked_mul(height)
        .and_then(|n| n.checked_mul(fmt.bytes_per_pixel()))
    else {
        return errno(EINVAL);
    };
    let pages = byte_size.div_ceil(PAGE_SIZE) as usize;
    let mut frames: Vec<PhysAddr> = Vec::with_capacity(pages);
    for _ in 0..pages {
        match allocate_frame() {
            Some(pa) => frames.push(pa),
            None => {
                for f in frames {
                    let _ = deallocate_frame(f);
                }
                return errno(ENOMEM);
            }
        }
    }
    let id = insert(Surface { owner_pid: proc.pid(), width, height, fmt, frames });
    SyscallResult { value: id as i64, capability_consumed: false, audit_required: true }
}
