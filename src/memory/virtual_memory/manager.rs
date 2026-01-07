// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use alloc::vec::Vec;
use x86_64::VirtAddr;
use super::constants::*;
use super::stats::VirtualMemoryStatistics;
use super::types::{AddressSpace, VmArea, VmProtection, VmStats, VmType};
use crate::memory::{frame_alloc, layout, paging};
pub struct VirtualMemoryManager {
    vm_areas: BTreeMap<u64, VmArea>,
    address_spaces: BTreeMap<u32, AddressSpace>,
    next_area_id: u64,
    current_asid: u32,
    initialized: bool,
}

impl VirtualMemoryManager {
    pub const fn new() -> Self {
        Self {
            vm_areas: BTreeMap::new(),
            address_spaces: BTreeMap::new(),
            next_area_id: 1,
            current_asid: 0,
            initialized: false,
        }
    }

    pub fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized {
            return Ok(());
        }

        self.vm_areas.clear();
        self.address_spaces.clear();
        self.next_area_id = 1;
        self.create_kernel_address_space()?;
        self.initialized = true;

        Ok(())
    }

    fn create_kernel_address_space(&mut self) -> Result<(), &'static str> {
        let kernel_space = AddressSpace {
            asid: 0,
            page_table: paging::get_current_cr3(),
            vm_areas: Vec::new(),
            heap_start: VirtAddr::new(layout::KHEAP_BASE),
            heap_end: VirtAddr::new(layout::KHEAP_BASE + layout::KHEAP_SIZE),
            stack_start: VirtAddr::new(layout::KERNEL_BASE - layout::KSTACK_SIZE as u64),
            stack_end: VirtAddr::new(layout::KERNEL_BASE),
            mmap_start: VirtAddr::new(layout::VMAP_BASE),
            creation_time: get_timestamp(),
        };

        self.address_spaces.insert(0, kernel_space);
        self.current_asid = 0;
        Ok(())
    }

    pub fn create_address_space(&mut self, process_id: u32) -> Result<u32, &'static str> {
        let asid = paging::create_address_space(process_id)
            .map_err(|_| "Failed to create address space")?;
        let page_table = paging::get_current_cr3();
        let address_space = AddressSpace {
            asid,
            page_table,
            vm_areas: Vec::new(),
            heap_start: VirtAddr::new(USER_HEAP_START),
            heap_end: VirtAddr::new(USER_HEAP_START),
            stack_start: VirtAddr::new(USER_STACK_BOTTOM),
            stack_end: VirtAddr::new(USER_STACK_TOP),
            mmap_start: VirtAddr::new(USER_MMAP_START),
            creation_time: get_timestamp(),
        };

        self.address_spaces.insert(asid, address_space);
        Ok(asid)
    }

    pub fn switch_address_space(&mut self, asid: u32) -> Result<(), &'static str> {
        if !self.address_spaces.contains_key(&asid) {
            return Err("Address space not found");
        }

        paging::switch_address_space(asid)
            .map_err(|_| "Failed to switch address space")?;
        self.current_asid = asid;

        Ok(())
    }

    pub fn map_vm_area(
        &mut self,
        vm_area: VmArea,
        stats: &VirtualMemoryStatistics,
    ) -> Result<u64, &'static str> {
        if !self.initialized {
            return Err("Virtual memory manager not initialized");
        }

        if self.has_overlap(&vm_area) {
            return Err("VM area overlaps with existing area");
        }

        let area_id = self.next_area_id;
        self.next_area_id += 1;
        let page_permissions = protection_to_page_permissions(vm_area.protection);
        let page_count = (vm_area.size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        for i in 0..page_count {
            let va = VirtAddr::new(vm_area.start.as_u64() + (i * layout::PAGE_SIZE) as u64);
            if vm_area.vm_type.is_demand_paged() {
                let pa = frame_alloc::allocate_frame().ok_or("Failed to allocate physical frame")?;
                paging::map_page(va, pa, page_permissions)
                    .map_err(|_| "Failed to map page")?;
                // SAFETY: The physical address was just allocated and is valid.
                // We zero it via the direct map.
                unsafe {
                    let direct_va = layout::DIRECTMAP_BASE + pa.as_u64();
                    core::ptr::write_bytes(direct_va as *mut u8, 0, layout::PAGE_SIZE);
                }
            }
        }

        stats.record_vm_area(vm_area.size as u64, vm_area.vm_type);
        self.vm_areas.insert(area_id, vm_area);
        if let Some(address_space) = self.address_spaces.get_mut(&self.current_asid) {
            address_space.vm_areas.push(area_id);
        }

        Ok(area_id)
    }

    pub fn unmap_vm_area(
        &mut self,
        area_id: u64,
        stats: &VirtualMemoryStatistics,
    ) -> Result<(), &'static str> {
        let vm_area = self.vm_areas.remove(&area_id).ok_or("VM area not found")?;
        let page_count = (vm_area.size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        for i in 0..page_count {
            let va = VirtAddr::new(vm_area.start.as_u64() + (i * layout::PAGE_SIZE) as u64);
            if let Ok(pa) = paging::unmap_page(va) {
                frame_alloc::deallocate_frame(pa);
            }
        }

        if let Some(address_space) = self.address_spaces.get_mut(&self.current_asid) {
            address_space.vm_areas.retain(|&id| id != area_id);
        }

        stats.record_vm_area_removal(vm_area.size as u64, vm_area.vm_type);

        Ok(())
    }

    /// Changes VM area protection.
    pub fn protect_vm_area(
        &mut self,
        area_id: u64,
        new_protection: VmProtection,
    ) -> Result<(), &'static str> {
        let vm_area = self.vm_areas.get_mut(&area_id).ok_or("VM area not found")?;
        vm_area.protection = new_protection;
        let page_permissions = protection_to_page_permissions(new_protection);
        let page_count = (vm_area.size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        paging::protect_pages(vm_area.start, page_count, page_permissions)
            .map_err(|_| "Failed to protect pages")?;

        Ok(())
    }

    pub fn expand_heap(
        &mut self,
        new_size: usize,
        stats: &VirtualMemoryStatistics,
    ) -> Result<(), &'static str> {
        let current_asid = self.current_asid;
        let (heap_end, heap_start) = {
            let address_space = self
                .address_spaces
                .get(&current_asid)
                .ok_or("Address space not found")?;
            (address_space.heap_end, address_space.heap_start)
        };

        let current_heap_size = (heap_end.as_u64() - heap_start.as_u64()) as usize;

        if new_size <= current_heap_size {
            return Ok(());
        }

        let additional_size = new_size - current_heap_size;
        let new_heap_end = VirtAddr::new(heap_start.as_u64() + new_size as u64);
        let heap_area = VmArea::new(heap_end, additional_size, VmProtection::ReadWrite, VmType::Heap);
        self.map_vm_area(heap_area, stats)?;
        let address_space = self
            .address_spaces
            .get_mut(&current_asid)
            .ok_or("Address space not found")?;
        address_space.heap_end = new_heap_end;

        Ok(())
    }

    pub fn expand_stack(
        &mut self,
        additional_size: usize,
        stats: &VirtualMemoryStatistics,
    ) -> Result<(), &'static str> {
        let current_asid = self.current_asid;
        let stack_start = {
            let address_space = self
                .address_spaces
                .get(&current_asid)
                .ok_or("Address space not found")?;
            address_space.stack_start
        };

        let new_stack_start = VirtAddr::new(stack_start.as_u64() - additional_size as u64);
        let stack_area = VmArea::new(
            new_stack_start,
            additional_size,
            VmProtection::ReadWrite,
            VmType::Stack,
        );

        self.map_vm_area(stack_area, stats)?;
        let address_space = self
            .address_spaces
            .get_mut(&current_asid)
            .ok_or("Address space not found")?;
        address_space.stack_start = new_stack_start;

        Ok(())
    }

    pub fn handle_page_fault(
        &mut self,
        fault_addr: VirtAddr,
        error_code: u64,
        stats: &VirtualMemoryStatistics,
    ) -> Result<(), &'static str> {
        stats.record_page_fault();

        let vm_area = self
            .find_vm_area_by_address(fault_addr)
            .ok_or("No VM area for fault address")?;

        let area_id = self
            .find_vm_area_id_by_address(fault_addr)
            .ok_or("VM area ID not found")?;

        if error_code & PF_PRESENT != 0 && error_code & PF_WRITE != 0 {
            if vm_area.protection == VmProtection::Read
                || vm_area.protection == VmProtection::ReadExecute
            {
                stats.record_protection_fault();
                return Err("Write to read-only memory");
            }
        }

        if error_code & PF_INSTRUCTION != 0 {
            if vm_area.protection == VmProtection::Read
                || vm_area.protection == VmProtection::ReadWrite
            {
                stats.record_protection_fault();
                return Err("Execute on non-executable memory");
            }
        }

        paging::handle_page_fault(fault_addr, error_code)
            .map_err(|_| "Failed to handle page fault")?;
        if let Some(area) = self.vm_areas.get_mut(&area_id) {
            area.fault_count += 1;
            area.access_count += 1;
        }

        Ok(())
    }

    pub fn find_vm_area_by_address(&self, addr: VirtAddr) -> Option<&VmArea> {
        self.vm_areas.values().find(|area| area.contains(addr))
    }

    fn find_vm_area_id_by_address(&self, addr: VirtAddr) -> Option<u64> {
        self.vm_areas
            .iter()
            .find(|(_, area)| area.contains(addr))
            .map(|(&id, _)| id)
    }

    pub fn has_overlap(&self, vm_area: &VmArea) -> bool {
        self.vm_areas.values().any(|area| area.overlaps(vm_area))
    }

    pub fn merge_adjacent_areas(&mut self) {
        let mut areas_to_merge = Vec::new();
        let mut areas: Vec<_> = self.vm_areas.iter().collect();
        areas.sort_by_key(|(_, area)| area.start.as_u64());
        for window in areas.windows(2) {
            let (id1, area1) = window[0];
            let (id2, area2) = window[1];
            if area1.can_merge(area2) {
                areas_to_merge.push((*id1, *id2));
            }
        }

        for (id1, id2) in areas_to_merge {
            if let (Some(area1), Some(area2)) = (self.vm_areas.get(&id1), self.vm_areas.get(&id2)) {
                let merged_start = area1.start.min(area2.start);
                let merged_end = area1.end().max(area2.end());
                let merged_size = (merged_end.as_u64() - merged_start.as_u64()) as usize;
                let merged_area =
                    VmArea::new(merged_start, merged_size, area1.protection, area1.vm_type);
                self.vm_areas.remove(&id1);
                self.vm_areas.remove(&id2);
                self.vm_areas.insert(id1, merged_area);
            }
        }
    }

    pub fn get_vm_stats(&self, stats: &VirtualMemoryStatistics) -> VmStats {
        VmStats {
            total_vm_areas: self.vm_areas.len(),
            address_spaces: self.address_spaces.len(),
            total_virtual_memory: stats.total_virtual_memory(),
            heap_usage: stats.heap_usage(),
            stack_usage: stats.stack_usage(),
            mmap_usage: stats.mmap_usage(),
            page_faults: stats.page_faults(),
            protection_faults: stats.protection_faults(),
            swap_operations: stats.swap_operations(),
            tlb_shootdowns: stats.tlb_shootdowns(),
        }
    }
}

impl Default for VirtualMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

fn protection_to_page_permissions(protection: VmProtection) -> paging::PagePermissions {
    match protection {
        VmProtection::None => paging::PagePermissions::READ.remove(paging::PagePermissions::READ),
        VmProtection::Read => paging::PagePermissions::READ,
        VmProtection::ReadWrite => paging::PagePermissions::READ | paging::PagePermissions::WRITE,
        VmProtection::ReadExecute => {
            paging::PagePermissions::READ | paging::PagePermissions::EXECUTE
        }
        VmProtection::ReadWriteExecute => {
            paging::PagePermissions::READ
                | paging::PagePermissions::WRITE
                | paging::PagePermissions::EXECUTE
        }
    }
}

fn get_timestamp() -> u64 {
    // SAFETY: rdtsc is always safe on x86_64.
    unsafe { core::arch::x86_64::_rdtsc() }
}
// ============================================================================
// GLOBAL STATE
// ============================================================================
use spin::Mutex;
use x86_64::PhysAddr;
static VMEM_MANAGER: Mutex<VirtualMemoryManager> = Mutex::new(VirtualMemoryManager::new());
static VMEM_STATS: VirtualMemoryStatistics = VirtualMemoryStatistics::new();
// ============================================================================
// PUBLIC API
// ============================================================================
pub fn init() -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.init()
}

pub fn create_address_space(process_id: u32) -> Result<u32, &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.create_address_space(process_id)
}

pub fn switch_address_space(asid: u32) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.switch_address_space(asid)
}

pub fn map_memory_range(
    va: VirtAddr,
    size: usize,
    protection: VmProtection,
    vm_type: VmType,
) -> Result<u64, &'static str> {
    let vm_area = VmArea::new(va, size, protection, vm_type);
    let mut manager = VMEM_MANAGER.lock();
    manager.map_vm_area(vm_area, &VMEM_STATS)
}

pub fn unmap_memory_range(area_id: u64) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.unmap_vm_area(area_id, &VMEM_STATS)
}

pub fn protect_memory_range(area_id: u64, protection: VmProtection) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.protect_vm_area(area_id, protection)
}

pub fn expand_heap(new_size: usize) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.expand_heap(new_size, &VMEM_STATS)
}

pub fn expand_stack(additional_size: usize) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.expand_stack(additional_size, &VMEM_STATS)
}

pub fn handle_page_fault(fault_addr: VirtAddr, error_code: u64) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.handle_page_fault(fault_addr, error_code, &VMEM_STATS)
}

pub fn translate_address(va: VirtAddr) -> Option<PhysAddr> {
    paging::translate_address(va)
}

pub fn is_mapped(va: VirtAddr) -> bool {
    paging::is_mapped(va)
}

pub fn get_vm_stats() -> VmStats {
    let manager = VMEM_MANAGER.lock();
    manager.get_vm_stats(&VMEM_STATS)
}

pub fn merge_adjacent_areas() {
    let mut manager = VMEM_MANAGER.lock();
    manager.merge_adjacent_areas()
}

pub fn find_vm_area_by_address(addr: VirtAddr) -> Option<VmArea> {
    let manager = VMEM_MANAGER.lock();
    manager.find_vm_area_by_address(addr).cloned()
}

pub fn allocate_user_stack(size: usize) -> Result<VirtAddr, &'static str> {
    let stack_bottom = VirtAddr::new(USER_STACK_BOTTOM - size as u64);
    let _area_id = map_memory_range(stack_bottom, size, VmProtection::ReadWrite, VmType::Stack)?;
    Ok(stack_bottom)
}

pub fn allocate_user_heap(initial_size: usize) -> Result<VirtAddr, &'static str> {
    let heap_start = VirtAddr::new(USER_HEAP_START);
    let _area_id = map_memory_range(heap_start, initial_size, VmProtection::ReadWrite, VmType::Heap)?;
    Ok(heap_start)
}

pub fn allocate_shared_memory(size: usize) -> Result<VirtAddr, &'static str> {
    let shared_start = VirtAddr::new(SHARED_MEMORY_START);
    let _area_id = map_memory_range(shared_start, size, VmProtection::ReadWrite, VmType::Shared)?;
    Ok(shared_start)
}

pub fn flush_tlb_range(start: VirtAddr, size: usize) {
    let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    for i in 0..page_count {
        let va = VirtAddr::new(start.as_u64() + (i * layout::PAGE_SIZE) as u64);
        paging::invalidate_page(va);
    }
    VMEM_STATS.record_tlb_shootdowns(page_count as u64);
}

pub fn flush_all_tlb() {
    paging::invalidate_all_pages();
    VMEM_STATS.record_tlb_shootdowns(1);
}
