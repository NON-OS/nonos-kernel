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

use x86_64::VirtAddr;

use crate::syscall::SyscallResult;
use crate::syscall::extended::errno;

pub fn handle_mremap(old_addr: u64, old_size: u64, new_size: u64, flags: u64) -> SyscallResult {
    use crate::memory::phys::AllocFlags;
    use crate::memory::PhysAddr;

    const MREMAP_MAYMOVE: u64 = 1;
    const _MREMAP_FIXED: u64 = 2;

    if old_addr & 0xFFF != 0 {
        return errno(22);
    }

    if old_size == 0 || new_size == 0 {
        return errno(22);
    }

    let proc = match crate::process::current_process() {
        Some(p) => p,
        None => return errno(1),
    };

    let old_pages = (old_size + 4095) / 4096;
    let new_pages = (new_size + 4095) / 4096;

    if new_size <= old_size {
        let pages_to_free = old_pages - new_pages;
        for i in 0..pages_to_free {
            let page_va = VirtAddr::new(old_addr + (new_pages + i) * 4096);
            let _ = crate::memory::virt::unmap_page(page_va);
        }

        return SyscallResult {
            value: old_addr as i64,
            capability_consumed: false,
            audit_required: true
        };
    }

    let can_grow_in_place = {
        let mem = proc.memory.lock();
        let end_addr = old_addr + new_size as u64;

        let mut can_grow = true;
        for vma in &mem.vmas {
            let vma_start = vma.start.as_u64();
            let vma_end = vma.end.as_u64();

            if vma_start == old_addr {
                continue;
            }

            if old_addr + old_size < vma_end && end_addr > vma_start {
                can_grow = false;
                break;
            }
        }
        can_grow
    };

    if can_grow_in_place {
        let extra_pages = new_pages - old_pages;
        let _page_flags = x86_64::structures::paging::PageTableFlags::PRESENT
            | x86_64::structures::paging::PageTableFlags::WRITABLE
            | x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE
            | x86_64::structures::paging::PageTableFlags::NO_EXECUTE;

        for i in 0..extra_pages {
            let page_va = VirtAddr::new(old_addr + (old_pages + i) * 4096);

            let phys = match crate::memory::phys::allocate_frame(AllocFlags::ZERO) {
                Some(p) => p,
                None => return errno(12),
            };

            if let Err(_) = crate::memory::virt::map_page_4k(
                page_va,
                PhysAddr::new(phys.0),
                true,
                true,
                false,
            ) {
                return errno(12);
            }
        }

        return SyscallResult {
            value: old_addr as i64,
            capability_consumed: false,
            audit_required: true
        };
    }

    if (flags & MREMAP_MAYMOVE) == 0 {
        return errno(12);
    }

    let page_flags = x86_64::structures::paging::PageTableFlags::PRESENT
        | x86_64::structures::paging::PageTableFlags::WRITABLE
        | x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE
        | x86_64::structures::paging::PageTableFlags::NO_EXECUTE;

    let new_addr = match proc.mmap(None, new_size as usize, page_flags) {
        Ok(addr) => addr,
        Err(_) => return errno(12),
    };

    unsafe {
        core::ptr::copy_nonoverlapping(
            old_addr as *const u8,
            new_addr.as_u64() as *mut u8,
            old_size as usize,
        );
    }

    let _ = proc.munmap(VirtAddr::new(old_addr), old_size as usize);

    SyscallResult {
        value: new_addr.as_u64() as i64,
        capability_consumed: false,
        audit_required: true
    }
}
