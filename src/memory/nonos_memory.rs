#![no_std]

extern crate alloc;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::Mutex;
use x86_64::{VirtAddr, PhysAddr};
use crate::memory::nonos_layout as layout;
use crate::memory::nonos_alloc as mem_alloc;
use crate::memory::nonos_virt as virt;

static MEMORY_MANAGER: Mutex<MemoryManager> = Mutex::new(MemoryManager::new());
static MEMORY_STATS: MemoryStats = MemoryStats::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionType {
    Code,
    Data,
    Stack,
    Heap,
    Device,
    Capsule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    Public,
    Internal,
    Confidential,
    Secret,
    TopSecret,
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub region_id: u64,
    pub virtual_addr: VirtAddr,
    pub physical_addr: PhysAddr,
    pub size: usize,
    pub region_type: RegionType,
    pub security_level: SecurityLevel,
    pub owner_process: u64,
    pub encrypted: bool,
    pub creation_time: u64,
    pub access_count: u64,
}

struct MemoryManager {
    regions: BTreeMap<u64, MemoryRegion>,
    va_to_region: BTreeMap<u64, u64>,
    next_region_id: u64,
    initialized: bool,
}

struct MemoryStats {
    total_allocated: AtomicU64,
    region_count: AtomicUsize,
    allocations: AtomicU64,
    deallocations: AtomicU64,
    peak_usage: AtomicU64,
}

impl MemoryStats {
    const fn new() -> Self {
        Self {
            total_allocated: AtomicU64::new(0),
            region_count: AtomicUsize::new(0),
            allocations: AtomicU64::new(0),
            deallocations: AtomicU64::new(0),
            peak_usage: AtomicU64::new(0),
        }
    }

    fn record_allocation(&self, size: u64) {
        let new_total = self.total_allocated.fetch_add(size, Ordering::Relaxed) + size;
        self.region_count.fetch_add(1, Ordering::Relaxed);
        self.allocations.fetch_add(1, Ordering::Relaxed);

        loop {
            let current_peak = self.peak_usage.load(Ordering::Relaxed);
            if new_total <= current_peak {
                break;
            }
            if self.peak_usage.compare_exchange_weak(
                current_peak,
                new_total,
                Ordering::Relaxed,
                Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
    }

    fn record_deallocation(&self, size: u64) {
        self.total_allocated.fetch_sub(size, Ordering::Relaxed);
        self.region_count.fetch_sub(1, Ordering::Relaxed);
        self.deallocations.fetch_add(1, Ordering::Relaxed);
    }
}

impl MemoryManager {
    const fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
            va_to_region: BTreeMap::new(),
            next_region_id: 1,
            initialized: false,
        }
    }

    fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized {
            return Ok(());
        }

        self.regions.clear();
        self.va_to_region.clear();
        self.next_region_id = 1;
        self.initialized = true;

        Ok(())
    }

    fn allocate_region(&mut self, size: usize, region_type: RegionType, security_level: SecurityLevel, owner_process: u64) -> Result<VirtAddr, &'static str> {
        if !self.initialized {
            return Err("Memory manager not initialized");
        }

        if size == 0 {
            return Err("Invalid allocation size");
        }

        let va = self.allocate_virtual_memory(size, region_type)?;
        let pa = self.get_physical_address(va)?;

        let region_id = self.next_region_id;
        self.next_region_id += 1;

        let region = MemoryRegion {
            region_id,
            virtual_addr: va,
            physical_addr: pa,
            size,
            region_type,
            security_level,
            owner_process,
            encrypted: matches!(security_level, SecurityLevel::Secret | SecurityLevel::TopSecret),
            creation_time: self.get_timestamp(),
            access_count: 0,
        };

        self.regions.insert(region_id, region);
        self.va_to_region.insert(va.as_u64(), region_id);

        MEMORY_STATS.record_allocation(size as u64);

        Ok(va)
    }

    fn deallocate_region(&mut self, va: VirtAddr) -> Result<(), &'static str> {
        let region_id = self.va_to_region.remove(&va.as_u64())
            .ok_or("Address not found")?;

        let region = self.regions.remove(&region_id)
            .ok_or("Region not found")?;

        self.secure_zero_memory(va, region.size)?;
        self.free_virtual_memory(va, region.size)?;

        MEMORY_STATS.record_deallocation(region.size as u64);

        Ok(())
    }

    fn get_region_info(&self, va: VirtAddr) -> Option<&MemoryRegion> {
        let region_id = self.va_to_region.get(&va.as_u64())?;
        self.regions.get(region_id)
    }

    fn validate_access(&self, process_id: u64, va: VirtAddr, write: bool) -> bool {
        if let Some(region) = self.get_region_info(va) {
            if region.owner_process != process_id {
                return false;
            }

            match region.region_type {
                RegionType::Code => !write,
                RegionType::Data | RegionType::Stack | RegionType::Heap => true,
                RegionType::Device => true,
                RegionType::Capsule => region.security_level >= SecurityLevel::Confidential,
            }
        } else {
            false
        }
    }

    fn allocate_virtual_memory(&self, size: usize, region_type: RegionType) -> Result<VirtAddr, &'static str> {
        let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;

        let writable = matches!(region_type, RegionType::Data | RegionType::Stack | RegionType::Heap | RegionType::Device);
        let executable = matches!(region_type, RegionType::Code);

        mem_alloc::allocate_pages(page_count)
    }

    fn free_virtual_memory(&self, va: VirtAddr, size: usize) -> Result<(), &'static str> {
        let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        mem_alloc::free_pages(va, page_count)
    }

    fn get_physical_address(&self, va: VirtAddr) -> Result<PhysAddr, &'static str> {
        virt::translate_addr(va).map_err(|_| "Address translation failed")
    }

    fn secure_zero_memory(&self, va: VirtAddr, size: usize) -> Result<(), &'static str> {
        unsafe {
            core::ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size);
        }
        Ok(())
    }

    fn get_timestamp(&self) -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    fn get_stats(&self) -> ManagerStats {
        ManagerStats {
            total_regions: self.regions.len(),
            allocated_memory: MEMORY_STATS.total_allocated.load(Ordering::Relaxed),
            peak_memory: MEMORY_STATS.peak_usage.load(Ordering::Relaxed),
            allocations: MEMORY_STATS.allocations.load(Ordering::Relaxed),
            deallocations: MEMORY_STATS.deallocations.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
pub struct ManagerStats {
    pub total_regions: usize,
    pub allocated_memory: u64,
    pub peak_memory: u64,
    pub allocations: u64,
    pub deallocations: u64,
}

pub fn init() -> Result<(), &'static str> {
    let mut manager = MEMORY_MANAGER.lock();
    manager.init()
}

pub fn allocate_memory(size: usize, region_type: RegionType, security_level: SecurityLevel, owner_process: u64) -> Result<VirtAddr, &'static str> {
    let mut manager = MEMORY_MANAGER.lock();
    manager.allocate_region(size, region_type, security_level, owner_process)
}

pub fn deallocate_memory(va: VirtAddr) -> Result<(), &'static str> {
    let mut manager = MEMORY_MANAGER.lock();
    manager.deallocate_region(va)
}

pub fn get_region_info(va: VirtAddr) -> Option<MemoryRegion> {
    let manager = MEMORY_MANAGER.lock();
    manager.get_region_info(va).copied()
}

pub fn validate_memory_access(process_id: u64, va: VirtAddr, write: bool) -> bool {
    let manager = MEMORY_MANAGER.lock();
    manager.validate_access(process_id, va, write)
}

pub fn allocate_code_region(size: usize, owner_process: u64) -> Result<VirtAddr, &'static str> {
    allocate_memory(size, RegionType::Code, SecurityLevel::Public, owner_process)
}

pub fn allocate_data_region(size: usize, owner_process: u64) -> Result<VirtAddr, &'static str> {
    allocate_memory(size, RegionType::Data, SecurityLevel::Internal, owner_process)
}

pub fn allocate_heap_region(size: usize, owner_process: u64) -> Result<VirtAddr, &'static str> {
    allocate_memory(size, RegionType::Heap, SecurityLevel::Internal, owner_process)
}

pub fn allocate_stack_region(size: usize, owner_process: u64) -> Result<VirtAddr, &'static str> {
    allocate_memory(size, RegionType::Stack, SecurityLevel::Internal, owner_process)
}

pub fn allocate_secure_capsule(size: usize, owner_process: u64) -> Result<VirtAddr, &'static str> {
    allocate_memory(size, RegionType::Capsule, SecurityLevel::Secret, owner_process)
}

pub fn allocate_device_region(size: usize, owner_process: u64) -> Result<VirtAddr, &'static str> {
    allocate_memory(size, RegionType::Device, SecurityLevel::Public, owner_process)
}

pub fn zero_memory(va: VirtAddr, size: usize) -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size);
    }
    Ok(())
}

pub fn copy_memory(src: VirtAddr, dst: VirtAddr, size: usize) -> Result<(), &'static str> {
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr::<u8>(), dst.as_mut_ptr::<u8>(), size);
    }
    Ok(())
}

pub fn get_memory_stats() -> ManagerStats {
    let manager = MEMORY_MANAGER.lock();
    manager.get_stats()
}

pub fn get_total_memory() -> u64 {
    MEMORY_STATS.total_allocated.load(Ordering::Relaxed)
}

pub fn get_peak_memory() -> u64 {
    MEMORY_STATS.peak_usage.load(Ordering::Relaxed)
}

pub fn get_allocation_count() -> u64 {
    MEMORY_STATS.allocations.load(Ordering::Relaxed)
}

pub fn is_valid_address(va: VirtAddr) -> bool {
    let manager = MEMORY_MANAGER.lock();
    manager.get_region_info(va).is_some()
}