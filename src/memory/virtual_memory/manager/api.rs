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

use super::super::stats::VirtualMemoryStatistics;
use super::super::types::{VmArea, VmProtection, VmStats, VmType};
use super::core::VirtualMemoryManager;
use crate::memory::paging;
use spin::Mutex;
use crate::memory::addr::{PhysAddr, VirtAddr};

static VMEM_MANAGER: Mutex<VirtualMemoryManager> = Mutex::new(VirtualMemoryManager::new());
pub(super) static VMEM_STATS: VirtualMemoryStatistics = VirtualMemoryStatistics::new();

pub fn init() -> Result<(), &'static str> {
    VMEM_MANAGER.lock().init()
}
pub fn create_address_space(process_id: u32) -> Result<u32, &'static str> {
    VMEM_MANAGER.lock().create_address_space(process_id)
}
pub fn switch_address_space(asid: u32) -> Result<(), &'static str> {
    VMEM_MANAGER.lock().switch_address_space(asid)
}

pub fn map_memory_range(
    va: VirtAddr,
    size: usize,
    protection: VmProtection,
    vm_type: VmType,
) -> Result<u64, &'static str> {
    let vm_area = VmArea::new(va, size, protection, vm_type);
    VMEM_MANAGER.lock().map_vm_area(vm_area, &VMEM_STATS)
}

pub fn unmap_memory_range(area_id: u64) -> Result<(), &'static str> {
    VMEM_MANAGER.lock().unmap_vm_area(area_id, &VMEM_STATS)
}
pub fn protect_memory_range(area_id: u64, protection: VmProtection) -> Result<(), &'static str> {
    VMEM_MANAGER.lock().protect_vm_area(area_id, protection)
}
pub fn expand_heap(new_size: usize) -> Result<(), &'static str> {
    VMEM_MANAGER.lock().expand_heap(new_size, &VMEM_STATS)
}
pub fn expand_stack(additional_size: usize) -> Result<(), &'static str> {
    VMEM_MANAGER.lock().expand_stack(additional_size, &VMEM_STATS)
}

pub fn handle_page_fault(fault_addr: VirtAddr, error_code: u64) -> Result<(), &'static str> {
    VMEM_MANAGER.lock().handle_page_fault(fault_addr, error_code, &VMEM_STATS)
}

pub fn translate_address(va: VirtAddr) -> Option<PhysAddr> {
    paging::translate_address(va)
}
pub fn is_mapped(va: VirtAddr) -> bool {
    paging::is_mapped(va)
}
pub fn get_vm_stats() -> VmStats {
    VMEM_MANAGER.lock().get_vm_stats(&VMEM_STATS)
}
pub fn merge_adjacent_areas() {
    VMEM_MANAGER.lock().merge_adjacent_areas()
}
pub fn find_vm_area_by_address(addr: VirtAddr) -> Option<VmArea> {
    VMEM_MANAGER.lock().find_vm_area_by_address(addr).cloned()
}

pub use super::allocate::{allocate_shared_memory, allocate_user_heap, allocate_user_stack};
pub use super::tlb::{flush_all_tlb, flush_tlb_range};
