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

use crate::memory::addr::PhysAddr;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_from_user;

const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const ENOTSUP: i32 = 95;

pub(super) fn handle(display: u64, surface: u64) -> SyscallResult {
    if display != 0 {
        return super::super::util::errno(EINVAL);
    }
    let span = match super::graphics_unavailable::surface_span_for_id(surface) {
        Ok(v) => v,
        Err(e) => return super::super::util::errno(e),
    };
    let Some(handoff) = crate::boot::handoff::get_handoff() else {
        return super::super::util::errno(ENOTSUP);
    };
    let Some(fb) = handoff.framebuffer() else {
        return super::super::util::errno(ENOTSUP);
    };
    let Some(copy_len) = (fb.width as usize)
        .checked_mul(fb.height as usize)
        .and_then(|px| px.checked_mul(core::mem::size_of::<u32>()))
    else {
        return super::super::util::errno(EINVAL);
    };
    if span < copy_len {
        return super::super::util::errno(EINVAL);
    }
    let base = fb.ptr & !0xFFF;
    let offset = (fb.ptr - base) as usize;
    let Some(map_len) = offset.checked_add(copy_len) else {
        return super::super::util::errno(EINVAL);
    };
    let fb_va = match crate::memory::mmio::map_framebuffer(PhysAddr::new(base), map_len) {
        Ok(v) => v,
        Err(_) => return super::super::util::errno(ENOTSUP),
    };
    let mut bounce = [0u8; 4096];
    let dst = (fb_va.as_u64() + offset as u64) as *mut u8;
    let mut off = 0usize;
    while off < copy_len {
        let chunk = core::cmp::min(bounce.len(), copy_len - off);
        if copy_from_user(surface + off as u64, &mut bounce[..chunk]).is_err() {
            let _ = crate::memory::mmio::unmap_mmio(fb_va);
            return super::super::util::errno(EFAULT);
        }
        for i in 0..chunk {
            unsafe { core::ptr::write_volatile(dst.add(off + i), bounce[i]) };
        }
        off += chunk;
    }
    let _ = crate::memory::mmio::unmap_mmio(fb_va);
    SyscallResult::success_audited(0)
}
