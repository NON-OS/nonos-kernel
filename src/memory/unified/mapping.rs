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

use super::super::layout;
use super::super::paging::manager;
use super::super::paging::types::PagePermissions;
use super::types::{MemoryProtection, MemoryType};
use crate::memory::addr::VirtAddr;
use crate::memory::frame_alloc;

pub fn map_memory(
    va: VirtAddr,
    size: usize,
    protection: MemoryProtection,
    mem_type: MemoryType,
) -> Result<(), &'static str> {
    let mut perms = perms_from_protection(protection);
    if matches!(
        mem_type,
        MemoryType::UserCode
            | MemoryType::UserData
            | MemoryType::UserHeap
            | MemoryType::UserStack
            | MemoryType::SecureCapsule
    ) {
        perms = perms | PagePermissions::USER;
    }
    if matches!(mem_type, MemoryType::Device) {
        perms = perms | PagePermissions::NO_CACHE;
    }
    let pages = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    let mut mapped: usize = 0;
    for i in 0..pages {
        let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
        let frame = match frame_alloc::allocate_frame() {
            Some(f) => f,
            None => {
                rollback(va, mapped);
                return Err("frame allocation failed");
            }
        };
        if manager::map_page(page_va, frame, perms).is_err() {
            rollback(va, mapped);
            return Err("page mapping failed");
        }
        mapped = mapped.saturating_add(1);
    }
    Ok(())
}

pub fn unmap_memory(va: VirtAddr, size: usize) -> Result<(), &'static str> {
    let pages = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    for i in 0..pages {
        let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
        let _ = manager::unmap_page(page_va);
    }
    Ok(())
}

fn perms_from_protection(p: MemoryProtection) -> PagePermissions {
    match p {
        MemoryProtection::None => PagePermissions::READ,
        MemoryProtection::Read => PagePermissions::READ,
        MemoryProtection::ReadWrite => PagePermissions::READ | PagePermissions::WRITE,
        MemoryProtection::ReadExecute => PagePermissions::READ | PagePermissions::EXECUTE,
    }
}

fn rollback(start: VirtAddr, mapped: usize) {
    for i in 0..mapped {
        let page_va = VirtAddr::new(start.as_u64() + (i * layout::PAGE_SIZE) as u64);
        let _ = manager::unmap_page(page_va);
    }
}
