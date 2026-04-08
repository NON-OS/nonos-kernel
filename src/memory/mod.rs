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
pub mod boot_memory; pub mod buddy_alloc; pub mod dma; pub mod stats;
pub mod encryption; pub mod frame_alloc; pub mod hardening; pub mod heap;
pub mod kaslr; pub mod layout; pub mod mmio; pub mod mmu; pub mod page_allocator;
pub mod page_info; pub mod paging; pub mod phys; pub mod proof; pub mod region;
pub mod safety; pub mod secure_memory; pub mod unified; pub mod virt; pub mod virtual_memory;
#[cfg(test)] mod tests;

pub use x86_64::{PhysAddr, VirtAddr};
pub use buddy_alloc as allocator;
pub use frame_alloc as nonos_frame_alloc;
pub use layout as nonos_layout;
pub use paging as nonos_paging;
pub use secure_memory as memory;
pub use virt as nonos_virt;
pub use hardening::{get_all_process_regions, init_module_memory_protection, read_bytes,
    verify_kernel_data_integrity, verify_kernel_page_tables};
pub use unified::{allocate_secure_region, flush_tlb_all, flush_tlb_range, get_memory_system_stats,
    get_unified_vm_stats, handle_unified_page_fault, init_all_memory_subsystems,
    init_unified_vm, is_address_mapped, map_memory, phys_to_virt, translate_virtual,
    unmap_memory, validate_access, verify_all_memory_integrity, virt_to_phys,
    MemoryProtection, MemorySystemStats, MemoryType, UnifiedVmStats};

pub fn get_memory_stats() -> MemorySystemStats { get_memory_system_stats() }

pub fn read_process_memory(pid: u32, addr: u64, buf: &mut [u8]) -> Result<usize, i32> {
    let pcb = crate::process::PROCESS_TABLE.find_by_pid(pid).ok_or(-3)?;
    let mem = pcb.memory.lock();
    for vma in &mem.vmas {
        if addr >= vma.start.as_u64() && addr < vma.end.as_u64() {
            let max_len = (vma.end.as_u64() - addr) as usize;
            let copy_len = buf.len().min(max_len);
            unsafe { core::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), copy_len); }
            return Ok(copy_len);
        }
    }
    Err(-14)
}

pub fn get_process_vm_areas(pid: u32) -> alloc::vec::Vec<(u64, u64, u32)> {
    crate::process::PROCESS_TABLE.find_by_pid(pid).map(|pcb| {
        pcb.memory.lock().vmas.iter().map(|v| (v.start.as_u64(), v.end.as_u64(), v.flags.bits() as u32)).collect()
    }).unwrap_or_default()
}
