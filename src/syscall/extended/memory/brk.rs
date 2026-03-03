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

use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;
use spin::RwLock;
use x86_64::VirtAddr;

use crate::syscall::SyscallResult;
use crate::syscall::extended::errno;

static PROCESS_BRK: RwLock<BTreeMap<u32, u64>> = RwLock::new(BTreeMap::new());

pub fn handle_brk(addr: u64) -> SyscallResult {
    let proc = match crate::process::current_process() {
        Some(p) => p,
        None => return errno(1),
    };

    let pid = proc.pid;

    let mut brk_map = PROCESS_BRK.write();
    let current_brk = *brk_map.get(&pid).unwrap_or(&0x0000_1000_0000_0000);

    use crate::memory::phys::AllocFlags;
    use crate::memory::PhysAddr;

    if addr == 0 {
        return SyscallResult {
            value: current_brk as i64,
            capability_consumed: false,
            audit_required: false
        };
    }

    let page_aligned_addr = (addr + 4095) & !4095;

    const MIN_BRK: u64 = 0x0000_1000_0000_0000;
    const MAX_BRK: u64 = 0x0000_7F00_0000_0000;

    if page_aligned_addr < MIN_BRK || page_aligned_addr > MAX_BRK {
        return errno(12);
    }

    let current_page = (current_brk + 4095) & !4095;
    let new_page = page_aligned_addr;

    if new_page > current_page {
        let pages_to_allocate = (new_page - current_page) / 4096;

        for i in 0..pages_to_allocate {
            let page_va = VirtAddr::new(current_page + i * 4096);

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

        {
            let mem = proc.memory.lock();
            mem.resident_pages.fetch_add(pages_to_allocate, Ordering::Relaxed);
        }
    } else if new_page < current_page {
        let pages_to_free = (current_page - new_page) / 4096;

        for i in 0..pages_to_free {
            let page_va = VirtAddr::new(new_page + i * 4096);
            let _ = crate::memory::virt::unmap_page(page_va);
        }

        {
            let mem = proc.memory.lock();
            mem.resident_pages.fetch_sub(pages_to_free, Ordering::Relaxed);
        }
    }

    brk_map.insert(pid, page_aligned_addr);

    SyscallResult {
        value: page_aligned_addr as i64,
        capability_consumed: false,
        audit_required: false
    }
}
