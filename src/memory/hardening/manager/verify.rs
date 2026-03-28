// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use x86_64::VirtAddr;
use crate::memory::paging::PagePermissions;
use crate::memory::{dma, heap, kaslr, layout, mmio, paging, safety};
use super::super::constants::*;

pub fn init_module_memory_protection() {
    paging::enable_write_protection();
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
        if cr4 & CR4_SMEP == 0 { cr4 |= CR4_SMEP; }
        if cr4 & CR4_SMAP == 0 { cr4 |= CR4_SMAP; }
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
    }
}

pub fn verify_kernel_data_integrity() -> bool {
    if layout::validate_layout().is_err() { return false; }
    let current_cr3 = paging::get_current_cr3();
    if current_cr3.as_u64() == 0 { return false; }
    let current_cr4: u64;
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) current_cr4, options(nostack, preserves_flags)); }
    if (current_cr4 & CR4_REQUIRED_BITS) != CR4_REQUIRED_BITS { return false; }
    if !verify_kernel_page_tables() { return false; }
    let kernel_sections = layout::kernel_sections();
    for section in &kernel_sections {
        let va = VirtAddr::new(section.start);
        if let Some(pa) = paging::translate_address(va) {
            if pa.as_u64() == 0 || pa.as_u64() > layout::MAX_PHYS_ADDR { return false; }
            if let Some(perms) = paging::get_page_permissions(va) {
                if section.rx && !perms.contains(PagePermissions::EXECUTE) { return false; }
                if section.rw && !perms.contains(PagePermissions::WRITE) { return false; }
                if !section.rw && perms.contains(PagePermissions::WRITE) { return false; }
            } else { return false; }
        } else { return false; }
    }
    if !safety::verify_stack_integrity() { return false; }
    if !heap::verify_heap_integrity() { return false; }
    if !kaslr::verify_slide_integrity() { return false; }
    let kernel_entry_point = layout::KERNEL_BASE;
    if paging::translate_address(VirtAddr::new(kernel_entry_point)).is_some() {
        if let Ok(entry_bytes) = read_bytes(kernel_entry_point as usize, NOP_SLED_CHECK_SIZE) {
            if entry_bytes.iter().all(|&b| b == NOP_INSTRUCTION) { return false; }
            if entry_bytes.iter().all(|&b| b == 0x00) { return false; }
        } else { return false; }
    } else { return false; }
    true
}

pub fn verify_kernel_page_tables() -> bool {
    let current_cr3 = paging::get_current_cr3();
    if current_cr3.as_u64() == 0 { return false; }
    let kernel_sections = layout::kernel_sections();
    for section in &kernel_sections {
        let va = VirtAddr::new(section.start);
        if let Some(perms) = paging::get_page_permissions(va) {
            if section.rx && !perms.contains(PagePermissions::EXECUTE) { return false; }
            if section.rw && !perms.contains(PagePermissions::WRITE) { return false; }
        } else { return false; }
    }
    true
}

pub fn get_all_process_regions() -> alloc::vec::Vec<(VirtAddr, usize)> {
    let mut regions = alloc::vec::Vec::new();
    let kernel_sections = layout::kernel_sections();
    for section in &kernel_sections { regions.push((VirtAddr::new(section.start), section.size() as usize)); }
    if let Ok(heap_base) = layout::heap_base_for(0) { regions.push((VirtAddr::new(heap_base), layout::KHEAP_SIZE as usize)); }
    for region in layout::get_all_stack_regions() { regions.push((VirtAddr::new(region.base), region.size)); }
    for region in layout::get_percpu_regions() { regions.push((VirtAddr::new(region.base), region.size)); }
    for region in mmio::get_mapped_regions() { regions.push((region.va, region.size)); }
    for region in dma::get_allocated_regions() { regions.push((region.virt_addr, region.size)); }
    for region in layout::get_module_regions() { regions.push((VirtAddr::new(region.base), region.size)); }
    for region in safety::get_guard_regions() { regions.push((VirtAddr::new(region.start), (region.end - region.start) as usize)); }
    regions.sort_by_key(|&(addr, _)| addr.as_u64());
    regions.dedup_by(|a, b| { let a_end = a.0.as_u64() + a.1 as u64; let b_start = b.0.as_u64(); a_end > b_start && a.0.as_u64() <= b_start });
    regions
}

pub fn read_bytes(start: usize, size: usize) -> Result<&'static [u8], &'static str> {
    let va = VirtAddr::new(start as u64);
    if !paging::is_mapped(va) { return Err("Memory not mapped"); }
    let end_va = VirtAddr::new((start + size) as u64);
    if !paging::is_mapped(end_va) { return Err("End of range not mapped"); }
    unsafe { Ok(core::slice::from_raw_parts(start as *const u8, size)) }
}
