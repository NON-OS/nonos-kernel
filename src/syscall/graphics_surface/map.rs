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
use core::sync::atomic::{AtomicU64, Ordering};

use crate::capabilities::Capability;
use crate::memory::paging::{map_page, unmap_page, PagePermissions};
use crate::memory::VirtAddr;
use crate::syscall::dispatch::util::{errno, require_capability};
use crate::syscall::types::errnos::{EINVAL, ENOMEM};
use crate::syscall::SyscallResult;

use super::registry::{record_mapping, with_surface_frames, SurfaceId};

const PAGE_SIZE: u64 = 4096;
const SURFACE_VA_BASE: u64 = 0x0000_5000_0000;
const SURFACE_VA_MAX: u64 = 0x0000_6FFF_FFFF;

static NEXT_SURFACE_VA: AtomicU64 = AtomicU64::new(SURFACE_VA_BASE);

pub fn sys_surface_map(id: SurfaceId) -> SyscallResult {
    if let Err(e) = require_capability(Capability::GraphicsSurfaceMap) {
        return e;
    }
    let Some(proc) = crate::process::current_process() else {
        return errno(EINVAL);
    };
    let owner_pid = proc.pid();

    let frames: Vec<_> = match with_surface_frames(id, owner_pid) {
        Some(f) => f,
        None => return errno(EINVAL),
    };

    let span = (frames.len() as u64) * PAGE_SIZE;
    let base = NEXT_SURFACE_VA.fetch_add(span, Ordering::Relaxed);
    if base.saturating_add(span) > SURFACE_VA_MAX {
        return errno(ENOMEM);
    }

    let perms = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::USER;
    let mut mapped = 0usize;
    for (i, frame) in frames.iter().enumerate() {
        let va = VirtAddr::new(base + (i as u64) * PAGE_SIZE);
        if map_page(va, *frame, perms).is_err() {
            for j in 0..mapped {
                let _ = unmap_page(VirtAddr::new(base + (j as u64) * PAGE_SIZE));
            }
            return errno(ENOMEM);
        }
        mapped += 1;
    }

    if record_mapping(id, owner_pid, base).is_none() {
        for j in 0..mapped {
            let _ = unmap_page(VirtAddr::new(base + (j as u64) * PAGE_SIZE));
        }
        return errno(EINVAL);
    }

    SyscallResult { value: base as i64, capability_consumed: false, audit_required: true }
}
