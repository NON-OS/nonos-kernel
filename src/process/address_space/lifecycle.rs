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

//! Process address-space lifecycle. The functions here are the
//! process-layer expression of allocate / inherit / switch /
//! release. The underlying paging primitives are still x86_64-shaped
//! (CR3 handle, `paging::manager` API names); that flavor is held
//! below this boundary in `store_handle` and `load_handle`.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::elf::loader::LoadedSegment;
use crate::memory::addr::VirtAddr;
use crate::process::core::types::Vma;
use crate::process::core::ProcessControlBlock;

pub fn allocate(pcb: &Arc<ProcessControlBlock>) -> Result<(), &'static str> {
    crate::memory::paging::manager::create_address_space(pcb.pid)
        .map_err(|_| "failed to allocate process address space")?;
    let handle = crate::memory::paging::manager::get_process_cr3(pcb.pid)
        .ok_or("address space created but handle not retrievable")?;
    store_handle(pcb, handle);
    Ok(())
}

pub fn inherit(pcb: &Arc<ProcessControlBlock>, parent: &Arc<ProcessControlBlock>) {
    store_handle(pcb, load_handle(parent));
}

pub fn switch_to(pid: u32) -> Result<(), &'static str> {
    crate::memory::paging::manager::switch_to_process_address_space(pid)
        .map_err(|_| "failed to switch process address space")
}

pub fn map_user_stack(
    pcb: &Arc<ProcessControlBlock>,
    top: VirtAddr,
    size: usize,
) -> Result<(), &'static str> {
    use x86_64::structures::paging::PageTableFlags;
    let bottom = top.as_u64().saturating_sub(size as u64);
    let pages = (size + 4095) / 4096;
    let perms = crate::memory::paging::types::PagePermissions::user_rw();
    for i in 0..pages {
        let va = VirtAddr::new(bottom + (i as u64) * 4096);
        let pa = crate::memory::frame_alloc::allocate_frame()
            .ok_or("failed to allocate stack frame")?;
        crate::memory::paging::map_page(va, pa, perms)
            .map_err(|_| "failed to map stack page")?;
    }
    // The page at `bottom - 4096` is left unmapped as a guard.
    // A stack overflow that touches it faults through the trap policy
    // as SIGSEGV.
    let mut mem = pcb.memory.lock();
    mem.vmas.push(Vma {
        start: VirtAddr::new(bottom),
        end: top,
        flags: PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE,
    });
    Ok(())
}

pub fn record_segments(pcb: &Arc<ProcessControlBlock>, segments: &[LoadedSegment]) {
    let mut mem = pcb.memory.lock();
    for seg in segments {
        let start = seg.vaddr;
        let end = VirtAddr::new(seg.vaddr.as_u64() + seg.size as u64);
        mem.vmas.push(Vma { start, end, flags: seg.flags });
    }
}

pub fn release(pcb: &Arc<ProcessControlBlock>) {
    let mut mem = pcb.memory.lock();
    for vma in mem.vmas.drain(..) {
        let span = vma.end.as_u64().saturating_sub(vma.start.as_u64());
        let pages = (span + 4095) / 4096;
        for i in 0..pages {
            let va = VirtAddr::new(vma.start.as_u64() + i * 4096);
            if let Ok(phys) = crate::memory::paging::unmap_page(va) {
                let _ = crate::memory::frame_alloc::deallocate_frame(phys);
            }
        }
    }
    mem.resident_pages.store(0, Ordering::Release);
    drop(mem);
    if let Some(asid) = crate::memory::paging::manager::lookup_asid_for_process(pcb.pid) {
        let _ = crate::memory::paging::manager::cleanup_address_space(asid);
    }
}

fn store_handle(pcb: &Arc<ProcessControlBlock>, handle: u64) {
    pcb.cr3.store(handle, Ordering::Release);
}

fn load_handle(pcb: &Arc<ProcessControlBlock>) -> u64 {
    pcb.cr3.load(Ordering::Acquire)
}
