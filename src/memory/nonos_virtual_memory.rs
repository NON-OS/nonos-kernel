#![no_std]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::{VirtAddr, PhysAddr};
use crate::memory::{
    nonos_layout as layout,
    nonos_frame_alloc as frame_alloc,
    nonos_paging as paging,
    nonos_region as region,
};

static VMEM_MANAGER: Mutex<VirtualMemoryManager> = Mutex::new(VirtualMemoryManager::new());
static VMEM_STATS: VirtualMemoryStatistics = VirtualMemoryStatistics::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmProtection {
    None,
    Read,
    ReadWrite,
    ReadExecute,
    ReadWriteExecute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmType {
    Anonymous,
    File,
    Device,
    Shared,
    Stack,
    Heap,
    Code,
    Data,
}

#[derive(Debug, Clone)]
pub struct VmArea {
    pub start: VirtAddr,
    pub size: usize,
    pub protection: VmProtection,
    pub vm_type: VmType,
    pub flags: u32,
    pub creation_time: u64,
    pub access_count: u64,
    pub fault_count: u64,
}

impl VmArea {
    pub fn new(start: VirtAddr, size: usize, protection: VmProtection, vm_type: VmType) -> Self {
        Self {
            start,
            size,
            protection,
            vm_type,
            flags: 0,
            creation_time: get_timestamp(),
            access_count: 0,
            fault_count: 0,
        }
    }

    pub fn end(&self) -> VirtAddr {
        VirtAddr::new(self.start.as_u64() + self.size as u64)
    }

    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.start && addr < self.end()
    }

    pub fn overlaps(&self, other: &VmArea) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    pub fn can_merge(&self, other: &VmArea) -> bool {
        self.protection == other.protection 
            && self.vm_type == other.vm_type
            && (self.end() == other.start || other.end() == self.start)
    }
}

struct VirtualMemoryManager {
    vm_areas: BTreeMap<u64, VmArea>,
    address_spaces: BTreeMap<u32, AddressSpace>,
    next_area_id: u64,
    current_asid: u32,
    initialized: bool,
}

#[derive(Debug, Clone)]
struct AddressSpace {
    asid: u32,
    page_table: PhysAddr,
    vm_areas: Vec<u64>,
    heap_start: VirtAddr,
    heap_end: VirtAddr,
    stack_start: VirtAddr,
    stack_end: VirtAddr,
    mmap_start: VirtAddr,
    creation_time: u64,
}

struct VirtualMemoryStatistics {
    total_vm_areas: AtomicUsize,
    total_virtual_memory: AtomicU64,
    heap_usage: AtomicU64,
    stack_usage: AtomicU64,
    mmap_usage: AtomicU64,
    page_faults: AtomicU64,
    protection_faults: AtomicU64,
    swap_operations: AtomicU64,
    tlb_shootdowns: AtomicU64,
}

impl VirtualMemoryStatistics {
    const fn new() -> Self {
        Self {
            total_vm_areas: AtomicUsize::new(0),
            total_virtual_memory: AtomicU64::new(0),
            heap_usage: AtomicU64::new(0),
            stack_usage: AtomicU64::new(0),
            mmap_usage: AtomicU64::new(0),
            page_faults: AtomicU64::new(0),
            protection_faults: AtomicU64::new(0),
            swap_operations: AtomicU64::new(0),
            tlb_shootdowns: AtomicU64::new(0),
        }
    }

    fn record_vm_area(&self, size: u64, vm_type: VmType) {
        self.total_vm_areas.fetch_add(1, Ordering::Relaxed);
        self.total_virtual_memory.fetch_add(size, Ordering::Relaxed);

        match vm_type {
            VmType::Heap => { self.heap_usage.fetch_add(size, Ordering::Relaxed); },
            VmType::Stack => { self.stack_usage.fetch_add(size, Ordering::Relaxed); },
            VmType::Anonymous | VmType::File | VmType::Shared => {
                self.mmap_usage.fetch_add(size, Ordering::Relaxed);
            },
            _ => {},
        };
    }

    fn record_vm_area_removal(&self, size: u64, vm_type: VmType) {
        self.total_vm_areas.fetch_sub(1, Ordering::Relaxed);
        self.total_virtual_memory.fetch_sub(size, Ordering::Relaxed);

        match vm_type {
            VmType::Heap => { self.heap_usage.fetch_sub(size, Ordering::Relaxed); },
            VmType::Stack => { self.stack_usage.fetch_sub(size, Ordering::Relaxed); },
            VmType::Anonymous | VmType::File | VmType::Shared => { 
                self.mmap_usage.fetch_sub(size, Ordering::Relaxed);
            },
            _ => {},
        };
    }
}

impl VirtualMemoryManager {
    const fn new() -> Self {
        Self {
            vm_areas: BTreeMap::new(),
            address_spaces: BTreeMap::new(),
            next_area_id: 1,
            current_asid: 0,
            initialized: false,
        }
    }

    fn init(&mut self) -> Result<(), &'static str> {
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

    fn create_address_space(&mut self, process_id: u32) -> Result<u32, &'static str> {
        let asid = paging::create_address_space(process_id)?;
        let page_table = paging::get_current_cr3();

        let address_space = AddressSpace {
            asid,
            page_table,
            vm_areas: Vec::new(),
            heap_start: VirtAddr::new(0x10000000),
            heap_end: VirtAddr::new(0x10000000),
            stack_start: VirtAddr::new(0x70000000),
            stack_end: VirtAddr::new(0x80000000),
            mmap_start: VirtAddr::new(0x40000000),
            creation_time: get_timestamp(),
        };

        self.address_spaces.insert(asid, address_space);

        Ok(asid)
    }

    fn switch_address_space(&mut self, asid: u32) -> Result<(), &'static str> {
        if !self.address_spaces.contains_key(&asid) {
            return Err("Address space not found");
        }

        paging::switch_address_space(asid)?;
        self.current_asid = asid;

        Ok(())
    }

    fn map_vm_area(&mut self, vm_area: VmArea) -> Result<u64, &'static str> {
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
            
            if vm_area.vm_type == VmType::Anonymous || vm_area.vm_type == VmType::Heap || vm_area.vm_type == VmType::Stack {
                let pa = frame_alloc::allocate_frame()
                    .ok_or("Failed to allocate physical frame")?;
                paging::map_page(va, pa, page_permissions)?;

                unsafe {
                    let direct_va = layout::DIRECTMAP_BASE + pa.as_u64();
                    core::ptr::write_bytes(direct_va as *mut u8, 0, layout::PAGE_SIZE);
                }
            }
        }

        VMEM_STATS.record_vm_area(vm_area.size as u64, vm_area.vm_type);
        
        self.vm_areas.insert(area_id, vm_area);

        if let Some(address_space) = self.address_spaces.get_mut(&self.current_asid) {
            address_space.vm_areas.push(area_id);
        }

        Ok(area_id)
    }

    fn unmap_vm_area(&mut self, area_id: u64) -> Result<(), &'static str> {
        let vm_area = self.vm_areas.remove(&area_id)
            .ok_or("VM area not found")?;

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

        VMEM_STATS.record_vm_area_removal(vm_area.size as u64, vm_area.vm_type);

        Ok(())
    }

    fn protect_vm_area(&mut self, area_id: u64, new_protection: VmProtection) -> Result<(), &'static str> {
        let vm_area = self.vm_areas.get_mut(&area_id)
            .ok_or("VM area not found")?;

        vm_area.protection = new_protection;
        
        let page_permissions = protection_to_page_permissions(new_protection);
        let page_count = (vm_area.size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;

        paging::protect_pages(vm_area.start, page_count, page_permissions)?;

        Ok(())
    }

    fn expand_heap(&mut self, new_size: usize) -> Result<(), &'static str> {
        let current_asid = self.current_asid;
        let (heap_end, heap_start) = {
            let address_space = self.address_spaces.get(&current_asid)
                .ok_or("Address space not found")?;
            (address_space.heap_end, address_space.heap_start)
        };

        let current_heap_size = (heap_end.as_u64() - heap_start.as_u64()) as usize;
        
        if new_size <= current_heap_size {
            return Ok(());
        }

        let additional_size = new_size - current_heap_size;
        let new_heap_end = VirtAddr::new(heap_start.as_u64() + new_size as u64);

        let heap_area = VmArea::new(
            heap_end,
            additional_size,
            VmProtection::ReadWrite,
            VmType::Heap,
        );

        self.map_vm_area(heap_area)?;
        
        let address_space = self.address_spaces.get_mut(&current_asid)
            .ok_or("Address space not found")?;
        address_space.heap_end = new_heap_end;

        Ok(())
    }

    fn expand_stack(&mut self, additional_size: usize) -> Result<(), &'static str> {
        let current_asid = self.current_asid;
        let stack_start = {
            let address_space = self.address_spaces.get(&current_asid)
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

        self.map_vm_area(stack_area)?;
        
        let address_space = self.address_spaces.get_mut(&current_asid)
            .ok_or("Address space not found")?;
        address_space.stack_start = new_stack_start;

        Ok(())
    }

    fn handle_page_fault(&mut self, fault_addr: VirtAddr, error_code: u64) -> Result<(), &'static str> {
        VMEM_STATS.page_faults.fetch_add(1, Ordering::Relaxed);

        let vm_area = self.find_vm_area_by_address(fault_addr)
            .ok_or("No VM area for fault address")?;

        let area_id = self.find_vm_area_id_by_address(fault_addr)
            .ok_or("VM area ID not found")?;

        if error_code & 0x01 != 0 && error_code & 0x02 != 0 {
            if vm_area.protection == VmProtection::Read || vm_area.protection == VmProtection::ReadExecute {
                VMEM_STATS.protection_faults.fetch_add(1, Ordering::Relaxed);
                return Err("Write to read-only memory");
            }
        }

        if error_code & 0x10 != 0 {
            if vm_area.protection == VmProtection::Read || vm_area.protection == VmProtection::ReadWrite {
                VMEM_STATS.protection_faults.fetch_add(1, Ordering::Relaxed);
                return Err("Execute on non-executable memory");
            }
        }

        paging::handle_page_fault(fault_addr, error_code)?;

        if let Some(area) = self.vm_areas.get_mut(&area_id) {
            area.fault_count += 1;
            area.access_count += 1;
        }

        Ok(())
    }

    fn find_vm_area_by_address(&self, addr: VirtAddr) -> Option<&VmArea> {
        self.vm_areas.values().find(|area| area.contains(addr))
    }

    fn find_vm_area_id_by_address(&self, addr: VirtAddr) -> Option<u64> {
        self.vm_areas.iter()
            .find(|(_, area)| area.contains(addr))
            .map(|(&id, _)| id)
    }

    fn has_overlap(&self, vm_area: &VmArea) -> bool {
        self.vm_areas.values().any(|area| area.overlaps(vm_area))
    }

    fn merge_adjacent_areas(&mut self) {
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

                let merged_area = VmArea::new(
                    merged_start,
                    merged_size,
                    area1.protection,
                    area1.vm_type,
                );

                self.vm_areas.remove(&id1);
                self.vm_areas.remove(&id2);
                self.vm_areas.insert(id1, merged_area);
            }
        }
    }

    fn get_vm_stats(&self) -> VmStats {
        VmStats {
            total_vm_areas: self.vm_areas.len(),
            address_spaces: self.address_spaces.len(),
            total_virtual_memory: VMEM_STATS.total_virtual_memory.load(Ordering::Relaxed),
            heap_usage: VMEM_STATS.heap_usage.load(Ordering::Relaxed),
            stack_usage: VMEM_STATS.stack_usage.load(Ordering::Relaxed),
            mmap_usage: VMEM_STATS.mmap_usage.load(Ordering::Relaxed),
            page_faults: VMEM_STATS.page_faults.load(Ordering::Relaxed),
            protection_faults: VMEM_STATS.protection_faults.load(Ordering::Relaxed),
            swap_operations: VMEM_STATS.swap_operations.load(Ordering::Relaxed),
            tlb_shootdowns: VMEM_STATS.tlb_shootdowns.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
pub struct VmStats {
    pub total_vm_areas: usize,
    pub address_spaces: usize,
    pub total_virtual_memory: u64,
    pub heap_usage: u64,
    pub stack_usage: u64,
    pub mmap_usage: u64,
    pub page_faults: u64,
    pub protection_faults: u64,
    pub swap_operations: u64,
    pub tlb_shootdowns: u64,
}

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

pub fn map_memory_range(va: VirtAddr, size: usize, protection: VmProtection, vm_type: VmType) -> Result<u64, &'static str> {
    let vm_area = VmArea::new(va, size, protection, vm_type);
    let mut manager = VMEM_MANAGER.lock();
    manager.map_vm_area(vm_area)
}

pub fn unmap_memory_range(area_id: u64) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.unmap_vm_area(area_id)
}

pub fn protect_memory_range(area_id: u64, protection: VmProtection) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.protect_vm_area(area_id, protection)
}

pub fn expand_heap(new_size: usize) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.expand_heap(new_size)
}

pub fn expand_stack(additional_size: usize) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.expand_stack(additional_size)
}

pub fn handle_page_fault(fault_addr: VirtAddr, error_code: u64) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    manager.handle_page_fault(fault_addr, error_code)
}

pub fn translate_address(va: VirtAddr) -> Option<PhysAddr> {
    paging::translate_address(va)
}

pub fn is_mapped(va: VirtAddr) -> bool {
    paging::is_mapped(va)
}

pub fn get_vm_stats() -> VmStats {
    let manager = VMEM_MANAGER.lock();
    manager.get_vm_stats()
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
    let stack_bottom = VirtAddr::new(0x70000000 - size as u64);
    let area_id = map_memory_range(stack_bottom, size, VmProtection::ReadWrite, VmType::Stack)?;
    Ok(stack_bottom)
}

pub fn allocate_user_heap(initial_size: usize) -> Result<VirtAddr, &'static str> {
    let heap_start = VirtAddr::new(0x10000000);
    let area_id = map_memory_range(heap_start, initial_size, VmProtection::ReadWrite, VmType::Heap)?;
    Ok(heap_start)
}

pub fn allocate_shared_memory(size: usize) -> Result<VirtAddr, &'static str> {
    let shared_start = VirtAddr::new(0x50000000);
    let area_id = map_memory_range(shared_start, size, VmProtection::ReadWrite, VmType::Shared)?;
    Ok(shared_start)
}

pub fn flush_tlb_range(start: VirtAddr, size: usize) {
    let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    for i in 0..page_count {
        let va = VirtAddr::new(start.as_u64() + (i * layout::PAGE_SIZE) as u64);
        paging::invalidate_page(va);
    }
    VMEM_STATS.tlb_shootdowns.fetch_add(page_count as u64, Ordering::Relaxed);
}

pub fn flush_all_tlb() {
    paging::invalidate_all_pages();
    VMEM_STATS.tlb_shootdowns.fetch_add(1, Ordering::Relaxed);
}

fn protection_to_page_permissions(protection: VmProtection) -> paging::PagePermissions {
    match protection {
        VmProtection::None => paging::PagePermissions::READ.remove(paging::PagePermissions::READ),
        VmProtection::Read => paging::PagePermissions::READ,
        VmProtection::ReadWrite => paging::PagePermissions::READ | paging::PagePermissions::WRITE,
        VmProtection::ReadExecute => paging::PagePermissions::READ | paging::PagePermissions::EXECUTE,
        VmProtection::ReadWriteExecute => paging::PagePermissions::READ | paging::PagePermissions::WRITE | paging::PagePermissions::EXECUTE,
    }
}

fn get_timestamp() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}