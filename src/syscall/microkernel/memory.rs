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

use super::errnos::{ERRNO_INVAL, ERRNO_NOMEM, ERRNO_PERM};
use crate::memory::paging::{map_page, unmap_page, PagePermissions};
use crate::memory::VirtAddr;

const PAGE_SIZE: usize = 4096;
const USER_MMAP_BASE: u64 = 0x0000_4000_0000;
const USER_SPACE_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;
const MAX_MMAP_SIZE: usize = 1 << 30;

pub const PROT_READ: u32 = 0x1;
pub const PROT_WRITE: u32 = 0x2;
pub const PROT_EXEC: u32 = 0x4;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_ANONYMOUS: u32 = 0x20;

static NEXT_USER_VA: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(USER_MMAP_BASE);

#[inline]
fn is_user_space(addr: u64, len: usize) -> bool {
    addr <= USER_SPACE_MAX && len <= (USER_SPACE_MAX - addr) as usize
}

pub fn sys_mmap(addr: u64, length: usize, prot: u32, _flags: u32) -> i64 {
    if length == 0 || length > MAX_MMAP_SIZE {
        return ERRNO_INVAL;
    }
    if addr != 0 && !is_user_space(addr, length) {
        return ERRNO_PERM;
    }
    let pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    let mut perms = PagePermissions::READ | PagePermissions::USER;
    if prot & PROT_WRITE != 0 {
        perms = perms | PagePermissions::WRITE;
    }
    if prot & PROT_EXEC != 0 {
        perms = perms | PagePermissions::EXECUTE;
    }
    let bump = (pages * PAGE_SIZE) as u64;
    let allocated_va = addr == 0;
    let base = if !allocated_va {
        VirtAddr::new(addr)
    } else {
        let va = NEXT_USER_VA.fetch_add(bump, core::sync::atomic::Ordering::Relaxed);
        if va > USER_SPACE_MAX {
            return ERRNO_NOMEM;
        }
        VirtAddr::new(va)
    };
    for i in 0..pages {
        let va = VirtAddr::new(base.as_u64() + (i * PAGE_SIZE) as u64);
        let frame = match crate::memory::frame_alloc::allocate_frame() {
            Some(pa) => pa,
            None => {
                rollback_mapped_pages(base.as_u64(), i);
                if allocated_va {
                    return_va(base.as_u64(), bump);
                }
                return ERRNO_NOMEM;
            }
        };
        if map_page(va, frame, perms).is_err() {
            let _ = crate::memory::frame_alloc::deallocate_frame(frame);
            rollback_mapped_pages(base.as_u64(), i);
            if allocated_va {
                return_va(base.as_u64(), bump);
            }
            return ERRNO_NOMEM;
        }
    }
    base.as_u64() as i64
}

// Best-effort VA reclaim on full mmap failure. Succeeds when no
// concurrent `sys_mmap` bumped past us between the failure and
// here; otherwise the range stays consumed.
fn return_va(base: u64, bump: u64) {
    let _ = NEXT_USER_VA.compare_exchange(
        base + bump,
        base,
        core::sync::atomic::Ordering::Relaxed,
        core::sync::atomic::Ordering::Relaxed,
    );
}

// Walk back over `installed` 4 KiB pages starting at `base_va`,
// unmapping each one and returning its frame to the allocator. Used
// only by `sys_mmap` on a partial-failure path; success leaves the
// caller's VA range fully mapped and never reaches here.
fn rollback_mapped_pages(base_va: u64, installed: usize) {
    for j in 0..installed {
        let va = VirtAddr::new(base_va + (j * PAGE_SIZE) as u64);
        if let Ok(phys) = unmap_page(va) {
            let _ = crate::memory::frame_alloc::deallocate_frame(phys);
        }
    }
}

pub fn sys_munmap(addr: u64, length: usize) -> i64 {
    if addr == 0 || length == 0 {
        return ERRNO_INVAL;
    }
    if addr % PAGE_SIZE as u64 != 0 {
        return ERRNO_INVAL;
    }
    let pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    for i in 0..pages {
        let va = VirtAddr::new(addr + (i * PAGE_SIZE) as u64);
        if let Ok(phys) = unmap_page(va) {
            let _ = crate::memory::frame_alloc::deallocate_frame(phys);
        }
    }
    0
}
