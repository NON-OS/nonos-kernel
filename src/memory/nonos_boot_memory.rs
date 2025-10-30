#![no_std]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};
use crate::memory::nonos_layout as layout;

static BOOT_MEMORY_MANAGER: Mutex<Option<BootMemoryManager>> = Mutex::new(None);
static TOTAL_MEMORY: AtomicU64 = AtomicU64::new(0);
static AVAILABLE_MEMORY: AtomicU64 = AtomicU64::new(0);
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BootHandoff {
    pub magic: u64,
    pub version: u16,
    pub flags: u16,
    pub memory_base: u64,
    pub memory_size: u64,
    pub kernel_base: u64,
    pub kernel_size: u64,
    pub capsule_base: u64,
    pub capsule_size: u64,
    pub entropy: [u8; 32],
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionType {
    Available,
    Reserved,
    Kernel,
    Capsule,
    Hardware,
    Defective,
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub region_type: RegionType,
    pub flags: u32,
}

impl MemoryRegion {
    pub const fn new(start: u64, end: u64, region_type: RegionType, flags: u32) -> Self {
        Self {
            start: PhysAddr::new(start),
            end: PhysAddr::new(end),
            region_type,
            flags,
        }
    }

    pub const fn size(&self) -> u64 {
        self.end.as_u64() - self.start.as_u64()
    }

    pub const fn contains(&self, addr: PhysAddr) -> bool {
        addr.as_u64() >= self.start.as_u64() && addr.as_u64() < self.end.as_u64()
    }

    pub const fn is_available(&self) -> bool {
        matches!(self.region_type, RegionType::Available)
    }
}

pub struct BootMemoryManager {
    regions: Vec<MemoryRegion>,
    next_free: PhysAddr,
    total_size: u64,
    allocated_size: u64,
    initialized: bool,
}

impl BootMemoryManager {
    const fn new() -> Self {
        Self {
            regions: Vec::new(),
            next_free: PhysAddr::new(0),
            total_size: 0,
            allocated_size: 0,
            initialized: false,
        }
    }

    fn init_from_handoff(&mut self, handoff_addr: u64) -> Result<(), &'static str> {
        if handoff_addr == 0 {
            return self.init_default();
        }

        let handoff = unsafe {
            let ptr = handoff_addr as *const BootHandoff;
            if ptr.is_null() {
                return self.init_default();
            }
            ptr.read_volatile()
        };

        if handoff.magic != 0x4E4F4E4F534F5300 || handoff.version != 1 {
            return self.init_default();
        }

        self.setup_regions_from_handoff(&handoff)?;
        self.validate_layout()?;
        self.initialized = true;

        Ok(())
    }

    fn init_default(&mut self) -> Result<(), &'static str> {
        self.regions.clear();

        self.add_region(0x0, 0x100000, RegionType::Reserved, 0);
        self.add_region(0x100000, 0x400000, RegionType::Kernel, 0);
        self.add_region(0x400000, 0x8000000, RegionType::Available, 0);
        self.add_region(0xB8000, 0xC0000, RegionType::Hardware, 0);
        self.add_region(0xFEC00000, 0xFEC01000, RegionType::Hardware, 0);
        self.add_region(0xFEE00000, 0xFEE01000, RegionType::Hardware, 0);

        self.find_next_free()?;
        self.calculate_totals();
        self.initialized = true;

        Ok(())
    }

    fn setup_regions_from_handoff(&mut self, handoff: &BootHandoff) -> Result<(), &'static str> {
        self.regions.clear();

        self.add_region(0x0, 0x100000, RegionType::Reserved, 0);

        if handoff.kernel_size > 0 {
            let kernel_end = handoff.kernel_base + handoff.kernel_size;
            self.add_region(handoff.kernel_base, kernel_end, RegionType::Kernel, 0);
        }

        if handoff.capsule_size > 0 {
            let capsule_end = handoff.capsule_base + handoff.capsule_size;
            self.add_region(handoff.capsule_base, capsule_end, RegionType::Capsule, 0);
        }

        if handoff.memory_size > 0 {
            let mem_start = self.align_up(handoff.memory_base, layout::PAGE_SIZE as u64);
            let mem_end = self.align_down(handoff.memory_base + handoff.memory_size, layout::PAGE_SIZE as u64);
            
            if mem_end > mem_start {
                self.add_region(mem_start, mem_end, RegionType::Available, 0);
            }
        }

        self.add_hardware_regions();
        self.sort_regions();
        self.find_next_free()?;
        self.calculate_totals();

        Ok(())
    }

    fn add_hardware_regions(&mut self) {
        self.add_region(0xB8000, 0xC0000, RegionType::Hardware, 0);
        self.add_region(0xA0000, 0x100000, RegionType::Hardware, 0);
        self.add_region(0xC0000000, 0x100000000, RegionType::Hardware, 0);
        self.add_region(0xFEC00000, 0xFEC01000, RegionType::Hardware, 0);
        self.add_region(0xFEE00000, 0xFEE01000, RegionType::Hardware, 0);
    }

    fn add_region(&mut self, start: u64, end: u64, region_type: RegionType, flags: u32) {
        if start >= end {
            return;
        }
        
        let region = MemoryRegion::new(start, end, region_type, flags);
        self.regions.push(region);
    }

    fn sort_regions(&mut self) {
        self.regions.sort_by_key(|r| r.start.as_u64());
    }

    fn find_next_free(&mut self) -> Result<(), &'static str> {
        for region in &self.regions {
            if region.is_available() && region.size() >= layout::PAGE_SIZE as u64 {
                self.next_free = region.start;
                return Ok(());
            }
        }
        Err("No available memory found")
    }

    fn calculate_totals(&mut self) {
        self.total_size = 0;
        for region in &self.regions {
            self.total_size += region.size();
        }
    }

    fn validate_layout(&self) -> Result<(), &'static str> {
        if self.regions.is_empty() {
            return Err("No memory regions defined");
        }

        let mut has_available = false;
        for region in &self.regions {
            if region.start >= region.end {
                return Err("Invalid region bounds");
            }
            if region.is_available() {
                has_available = true;
            }
        }

        if !has_available {
            return Err("No available memory regions");
        }

        Ok(())
    }

    fn allocate_aligned(&mut self, size: usize, align: usize) -> Result<PhysAddr, &'static str> {
        let needed = Self::align_up_static(size as u64, align as u64);
        let next_free_val = self.next_free.as_u64();
        
        for region in &mut self.regions {
            if !region.is_available() {
                continue;
            }

            let aligned_start = Self::align_up_static(next_free_val, align as u64);
            let aligned_end = aligned_start + needed;

            if aligned_start >= region.start.as_u64() && 
               aligned_end <= region.end.as_u64() {
                let result = PhysAddr::new(aligned_start);
                self.next_free = PhysAddr::new(aligned_end);
                self.allocated_size += needed;
                
                ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
                AVAILABLE_MEMORY.fetch_sub(needed, Ordering::Relaxed);
                
                return Ok(result);
            }
        }

        Err("Out of memory")
    }

    fn align_up_static(value: u64, align: u64) -> u64 {
        (value + align - 1) & !(align - 1)
    }

    fn get_region_stats(&self) -> RegionStats {
        let mut stats = RegionStats::default();
        
        for region in &self.regions {
            let size = region.size();
            stats.total_memory += size;
            
            match region.region_type {
                RegionType::Available => stats.available_memory += size,
                RegionType::Reserved => stats.reserved_memory += size,
                RegionType::Kernel => stats.kernel_memory += size,
                RegionType::Capsule => stats.capsule_memory += size,
                RegionType::Hardware => stats.hardware_memory += size,
                RegionType::Defective => stats.defective_memory += size,
            }
        }
        
        stats.allocated_memory = self.allocated_size;
        stats.region_count = self.regions.len();
        stats
    }

    const fn align_up(&self, addr: u64, align: u64) -> u64 {
        (addr + align - 1) & !(align - 1)
    }

    const fn align_down(&self, addr: u64, align: u64) -> u64 {
        addr & !(align - 1)
    }
}

#[derive(Debug, Default)]
pub struct RegionStats {
    pub total_memory: u64,
    pub available_memory: u64,
    pub allocated_memory: u64,
    pub reserved_memory: u64,
    pub kernel_memory: u64,
    pub capsule_memory: u64,
    pub hardware_memory: u64,
    pub defective_memory: u64,
    pub region_count: usize,
}

pub fn init(handoff_addr: u64) -> Result<(), &'static str> {
    let mut guard = BOOT_MEMORY_MANAGER.lock();
    if guard.is_some() {
        return Err("Boot memory already initialized");
    }

    let mut manager = BootMemoryManager::new();
    manager.init_from_handoff(handoff_addr)?;
    
    let stats = manager.get_region_stats();
    TOTAL_MEMORY.store(stats.total_memory, Ordering::Relaxed);
    AVAILABLE_MEMORY.store(stats.available_memory, Ordering::Relaxed);

    *guard = Some(manager);
    Ok(())
}

pub fn allocate_pages(count: usize) -> Result<PhysAddr, &'static str> {
    let mut guard = BOOT_MEMORY_MANAGER.lock();
    if let Some(ref mut manager) = *guard {
        manager.allocate_aligned(count * layout::PAGE_SIZE, layout::PAGE_SIZE)
    } else {
        Err("Boot memory not initialized")
    }
}

pub fn allocate_aligned(size: usize, align: usize) -> Result<PhysAddr, &'static str> {
    let mut guard = BOOT_MEMORY_MANAGER.lock();
    if let Some(ref mut manager) = *guard {
        manager.allocate_aligned(size, align)
    } else {
        Err("Boot memory not initialized")
    }
}

pub fn get_stats() -> Option<RegionStats> {
    let guard = BOOT_MEMORY_MANAGER.lock();
    guard.as_ref().map(|manager| manager.get_region_stats())
}

pub fn get_available_regions() -> Vec<MemoryRegion> {
    let guard = BOOT_MEMORY_MANAGER.lock();
    if let Some(ref manager) = *guard {
        manager.regions.iter()
            .filter(|r| r.is_available())
            .copied()
            .collect()
    } else {
        Vec::new()
    }
}

pub fn find_region(addr: PhysAddr) -> Option<MemoryRegion> {
    let guard = BOOT_MEMORY_MANAGER.lock();
    if let Some(ref manager) = *guard {
        manager.regions.iter()
            .find(|r| r.contains(addr))
            .copied()
    } else {
        None
    }
}

pub fn total_memory() -> u64 {
    TOTAL_MEMORY.load(Ordering::Relaxed)
}

pub fn available_memory() -> u64 {
    AVAILABLE_MEMORY.load(Ordering::Relaxed)
}

pub fn allocation_count() -> usize {
    ALLOCATION_COUNT.load(Ordering::Relaxed)
}