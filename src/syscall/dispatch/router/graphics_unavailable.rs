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
use x86_64::structures::paging::PageTableFlags;

const ENOTSUP: i32 = 95;
const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const PIXEL_FMT_ARGB8888: u64 = 1;

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
        SyscallNumber::GraphicsSurfaceCreate => handle_surface_create(display, out_w, out_h),
        SyscallNumber::GraphicsSurfaceDestroy => handle_surface_destroy(display),
        SyscallNumber::GraphicsSurfaceMap => handle_surface_map(display),
        SyscallNumber::GraphicsSurfacePresentFull => super::graphics_present::handle(display, out_w),
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

fn handle_surface_create(width: u64, height: u64, fmt: u64) -> SyscallResult {
    let Some(handoff) = crate::boot::handoff::get_handoff() else {
        return super::super::util::errno(ENOTSUP);
    };
    let Some(fb) = handoff.framebuffer() else {
        return super::super::util::errno(ENOTSUP);
    };
    if fmt != PIXEL_FMT_ARGB8888 || width != fb.width as u64 || height != fb.height as u64 {
        return super::super::util::errno(EINVAL);
    }
    let Some(byte_len) = (width as usize)
        .checked_mul(height as usize)
        .and_then(|px| px.checked_mul(core::mem::size_of::<u32>()))
    else {
        return super::super::util::errno(EINVAL);
    };
    let Some(proc) = crate::process::current_process() else {
        return super::super::util::errno(ENOTSUP);
    };
    match proc.mmap(None, byte_len, PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE) {
        Ok(va) => SyscallResult::success_audited(va.as_u64() as i64),
        Err("ENOMEM") => super::super::util::errno(ENOMEM),
        Err(_) => super::super::util::errno(EINVAL),
    }
}

fn handle_surface_map(id: u64) -> SyscallResult {
    match surface_span_for_id(id) {
        Ok(_) => SyscallResult::success_audited(id as i64),
        Err(e) => super::super::util::errno(e),
    }
}

fn handle_surface_destroy(id: u64) -> SyscallResult {
    let len = match surface_span_for_id(id) {
        Ok(v) => v,
        Err(e) => return super::super::util::errno(e),
    };
    let Some(proc) = crate::process::current_process() else {
        return super::super::util::errno(ENOTSUP);
    };
    match proc.munmap(crate::memory::addr::VirtAddr::new(id), len) {
        Ok(()) => SyscallResult::success_audited(0),
        Err(_) => super::super::util::errno(EINVAL),
    }
}

pub(super) fn surface_span_for_id(id: u64) -> Result<usize, i32> {
    if id == 0 {
        return Err(EINVAL);
    }
    let Some(proc) = crate::process::current_process() else {
        return Err(ENOTSUP);
    };
    let mem = proc.memory.lock();
    let Some(vma) = mem.vmas.iter().find(|v| v.start.as_u64() == id) else {
        return Err(EINVAL);
    };
    let len = vma.end.as_u64().saturating_sub(vma.start.as_u64()) as usize;
    if len == 0 {
        return Err(EINVAL);
    }
    Ok(len)
}
