#![no_std]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering, compiler_fence};
use core::ptr;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::Mutex;
use x86_64::{VirtAddr, PhysAddr};
use crate::memory::nonos_layout as layout;

static MMIO_MANAGER: Mutex<MmioManager> = Mutex::new(MmioManager::new());
static MMIO_STATS: MmioStats = MmioStats::new();

struct MmioManager {
    regions: BTreeMap<VirtAddr, MmioRegion>,
    next_vaddr: u64,
    initialized: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct MmioRegion {
    pub va: VirtAddr,
    pub pa: PhysAddr,
    pub size: usize,
    pub flags: MmioFlags,
    pub region_id: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct MmioFlags {
    pub cacheable: bool,
    pub write_combining: bool,
    pub user_accessible: bool,
    pub executable: bool,
}

impl Default for MmioFlags {
    fn default() -> Self {
        Self {
            cacheable: false,
            write_combining: false,
            user_accessible: false,
            executable: false,
        }
    }
}

struct MmioStats {
    total_regions: AtomicUsize,
    total_mapped_size: AtomicU64,
    read_operations: AtomicU64,
    write_operations: AtomicU64,
    next_region_id: AtomicU64,
}

impl MmioStats {
    const fn new() -> Self {
        Self {
            total_regions: AtomicUsize::new(0),
            total_mapped_size: AtomicU64::new(0),
            read_operations: AtomicU64::new(0),
            write_operations: AtomicU64::new(0),
            next_region_id: AtomicU64::new(1),
        }
    }

    fn next_id(&self) -> u64 {
        self.next_region_id.fetch_add(1, Ordering::Relaxed)
    }

    fn record_mapping(&self, size: usize) {
        self.total_regions.fetch_add(1, Ordering::Relaxed);
        self.total_mapped_size.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn record_unmapping(&self, size: usize) {
        self.total_regions.fetch_sub(1, Ordering::Relaxed);
        self.total_mapped_size.fetch_sub(size as u64, Ordering::Relaxed);
    }

    fn record_read(&self) {
        self.read_operations.fetch_add(1, Ordering::Relaxed);
    }

    fn record_write(&self) {
        self.write_operations.fetch_add(1, Ordering::Relaxed);
    }
}

impl MmioManager {
    const fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
            next_vaddr: layout::MMIO_BASE,
            initialized: false,
        }
    }

    fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized {
            return Ok(());
        }

        self.next_vaddr = layout::MMIO_BASE;
        self.regions.clear();
        self.initialized = true;

        Ok(())
    }

    fn allocate_virtual_range(&mut self, size: usize) -> Result<VirtAddr, &'static str> {
        if !self.initialized {
            return Err("MMIO manager not initialized");
        }

        let aligned_size = self.align_up(size, layout::PAGE_SIZE);
        let aligned_addr = self.align_up(self.next_vaddr as usize, layout::PAGE_SIZE) as u64;

        if aligned_addr + aligned_size as u64 > layout::MMIO_BASE + layout::MMIO_SIZE {
            return Err("MMIO virtual address space exhausted");
        }

        let virt_addr = VirtAddr::new(aligned_addr);
        self.next_vaddr = aligned_addr + aligned_size as u64;

        Ok(virt_addr)
    }

    fn map_region(&mut self, pa: PhysAddr, size: usize, flags: MmioFlags) -> Result<VirtAddr, &'static str> {
        if size == 0 {
            return Err("Invalid size");
        }

        if pa.as_u64() % layout::PAGE_SIZE as u64 != 0 {
            return Err("Physical address not page aligned");
        }

        let va = self.allocate_virtual_range(size)?;
        let aligned_size = self.align_up(size, layout::PAGE_SIZE);
        let page_count = aligned_size / layout::PAGE_SIZE;

        let vm_flags = self.mmio_flags_to_vm_flags(flags);

        for i in 0..page_count {
            let page_offset = i * layout::PAGE_SIZE;
            let page_va = VirtAddr::new(va.as_u64() + page_offset as u64);
            let page_pa = PhysAddr::new(pa.as_u64() + page_offset as u64);

            self.map_page(page_va, page_pa, vm_flags)?;
        }

        let region_id = MMIO_STATS.next_id();
        let region = MmioRegion {
            va,
            pa,
            size: aligned_size,
            flags,
            region_id,
        };

        self.regions.insert(va, region);
        MMIO_STATS.record_mapping(aligned_size);

        Ok(va)
    }

    fn unmap_region(&mut self, va: VirtAddr) -> Result<(), &'static str> {
        let region = self.regions.remove(&va)
            .ok_or("MMIO region not found")?;

        let page_count = region.size / layout::PAGE_SIZE;

        for i in 0..page_count {
            let page_offset = i * layout::PAGE_SIZE;
            let page_va = VirtAddr::new(va.as_u64() + page_offset as u64);
            self.unmap_page(page_va)?;
        }

        MMIO_STATS.record_unmapping(region.size);

        Ok(())
    }

    fn find_region(&self, va: VirtAddr) -> Option<&MmioRegion> {
        self.regions.iter()
            .find(|(_, region)| {
                let start = region.va.as_u64();
                let end = start + region.size as u64;
                va.as_u64() >= start && va.as_u64() < end
            })
            .map(|(_, region)| region)
    }

    fn validate_access(&self, va: VirtAddr, offset: usize, access_size: usize) -> Result<&MmioRegion, &'static str> {
        let region = self.find_region(va)
            .ok_or("Invalid MMIO base address")?;

        if offset + access_size > region.size {
            return Err("Access beyond region bounds");
        }

        Ok(region)
    }

    fn map_page(&self, va: VirtAddr, pa: PhysAddr, vm_flags: u32) -> Result<(), &'static str> {
        use crate::memory::nonos_virt;

        let writable = (vm_flags & 0x02) != 0;
        let executable = (vm_flags & 0x04) == 0;
        let user = (vm_flags & 0x08) != 0;

        unsafe {
            nonos_virt::map_page_4k(va, pa, writable, user, executable)
                .map_err(|_| "Failed to map MMIO page")?;
        }

        Ok(())
    }

    fn unmap_page(&self, va: VirtAddr) -> Result<(), &'static str> {
        use crate::memory::nonos_virt;

        unsafe {
            nonos_virt::unmap_page(va)
                .map_err(|_| "Failed to unmap MMIO page")?;
        }

        Ok(())
    }

    fn mmio_flags_to_vm_flags(&self, flags: MmioFlags) -> u32 {
        let mut vm_flags = 0x01;

        vm_flags |= 0x02;

        if !flags.executable {
            vm_flags |= 0x04;
        }

        if flags.user_accessible {
            vm_flags |= 0x08;
        }

        if !flags.cacheable {
            vm_flags |= 0x10;
        }

        if flags.write_combining {
            vm_flags |= 0x20;
        }

        vm_flags
    }

    const fn align_up(&self, value: usize, align: usize) -> usize {
        (value + align - 1) & !(align - 1)
    }
}

pub fn init() -> Result<(), &'static str> {
    let mut manager = MMIO_MANAGER.lock();
    manager.init()
}

pub fn map_mmio(pa: PhysAddr, size: usize, flags: MmioFlags) -> Result<VirtAddr, &'static str> {
    let mut manager = MMIO_MANAGER.lock();
    manager.map_region(pa, size, flags)
}

pub fn map_device_memory(pa: PhysAddr, size: usize) -> Result<VirtAddr, &'static str> {
    let flags = MmioFlags {
        cacheable: false,
        write_combining: false,
        user_accessible: false,
        executable: false,
    };
    map_mmio(pa, size, flags)
}

pub fn map_framebuffer(pa: PhysAddr, size: usize) -> Result<VirtAddr, &'static str> {
    let flags = MmioFlags {
        cacheable: false,
        write_combining: true,
        user_accessible: false,
        executable: false,
    };
    map_mmio(pa, size, flags)
}

pub fn unmap_mmio(va: VirtAddr) -> Result<(), &'static str> {
    let mut manager = MMIO_MANAGER.lock();
    manager.unmap_region(va)
}

pub unsafe fn read8(va: VirtAddr, offset: usize) -> Result<u8, &'static str> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, 1)?;
    
    let ptr = (va.as_u64() + offset as u64) as *const u8;
    compiler_fence(Ordering::SeqCst);
    let value = ptr::read_volatile(ptr);
    compiler_fence(Ordering::SeqCst);
    
    MMIO_STATS.record_read();
    Ok(value)
}

pub unsafe fn write8(va: VirtAddr, offset: usize, value: u8) -> Result<(), &'static str> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, 1)?;
    
    let ptr = (va.as_u64() + offset as u64) as *mut u8;
    compiler_fence(Ordering::SeqCst);
    ptr::write_volatile(ptr, value);
    compiler_fence(Ordering::SeqCst);
    
    MMIO_STATS.record_write();
    Ok(())
}

pub unsafe fn read16(va: VirtAddr, offset: usize) -> Result<u16, &'static str> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, 2)?;
    
    let ptr = (va.as_u64() + offset as u64) as *const u16;
    compiler_fence(Ordering::SeqCst);
    let value = ptr::read_volatile(ptr);
    compiler_fence(Ordering::SeqCst);
    
    MMIO_STATS.record_read();
    Ok(value)
}

pub unsafe fn write16(va: VirtAddr, offset: usize, value: u16) -> Result<(), &'static str> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, 2)?;
    
    let ptr = (va.as_u64() + offset as u64) as *mut u16;
    compiler_fence(Ordering::SeqCst);
    ptr::write_volatile(ptr, value);
    compiler_fence(Ordering::SeqCst);
    
    MMIO_STATS.record_write();
    Ok(())
}

pub unsafe fn read32(va: VirtAddr, offset: usize) -> Result<u32, &'static str> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, 4)?;
    
    let ptr = (va.as_u64() + offset as u64) as *const u32;
    compiler_fence(Ordering::SeqCst);
    let value = ptr::read_volatile(ptr);
    compiler_fence(Ordering::SeqCst);
    
    MMIO_STATS.record_read();
    Ok(value)
}

pub unsafe fn write32(va: VirtAddr, offset: usize, value: u32) -> Result<(), &'static str> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, 4)?;
    
    let ptr = (va.as_u64() + offset as u64) as *mut u32;
    compiler_fence(Ordering::SeqCst);
    ptr::write_volatile(ptr, value);
    compiler_fence(Ordering::SeqCst);
    
    MMIO_STATS.record_write();
    Ok(())
}

pub unsafe fn read64(va: VirtAddr, offset: usize) -> Result<u64, &'static str> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, 8)?;
    
    let ptr = (va.as_u64() + offset as u64) as *const u64;
    compiler_fence(Ordering::SeqCst);
    let value = ptr::read_volatile(ptr);
    compiler_fence(Ordering::SeqCst);
    
    MMIO_STATS.record_read();
    Ok(value)
}

pub unsafe fn write64(va: VirtAddr, offset: usize, value: u64) -> Result<(), &'static str> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, 8)?;
    
    let ptr = (va.as_u64() + offset as u64) as *mut u64;
    compiler_fence(Ordering::SeqCst);
    ptr::write_volatile(ptr, value);
    compiler_fence(Ordering::SeqCst);
    
    MMIO_STATS.record_write();
    Ok(())
}

pub fn get_region_info(va: VirtAddr) -> Option<MmioRegion> {
    let manager = MMIO_MANAGER.lock();
    manager.find_region(va).copied()
}

pub fn list_regions() -> Vec<MmioRegion> {
    let manager = MMIO_MANAGER.lock();
    manager.regions.values().copied().collect()
}

pub fn get_stats() -> MmioStatsSnapshot {
    MmioStatsSnapshot {
        total_regions: MMIO_STATS.total_regions.load(Ordering::Relaxed),
        total_mapped_size: MMIO_STATS.total_mapped_size.load(Ordering::Relaxed),
        read_operations: MMIO_STATS.read_operations.load(Ordering::Relaxed),
        write_operations: MMIO_STATS.write_operations.load(Ordering::Relaxed),
    }
}

#[derive(Debug)]
pub struct MmioStatsSnapshot {
    pub total_regions: usize,
    pub total_mapped_size: u64,
    pub read_operations: u64,
    pub write_operations: u64,
}

pub fn validate_mmio_access(va: VirtAddr, size: usize) -> bool {
    let manager = MMIO_MANAGER.lock();
    manager.find_region(va)
        .map(|region| {
            let region_end = region.va.as_u64() + region.size as u64;
            va.as_u64() + size as u64 <= region_end
        })
        .unwrap_or(false)
}

pub fn is_mmio_region(va: VirtAddr) -> bool {
    let manager = MMIO_MANAGER.lock();
    manager.find_region(va).is_some()
}

pub fn mmio_r8(va: VirtAddr) -> u8 {
    MMIO_STATS.record_read();
    unsafe { ptr::read_volatile(va.as_ptr()) }
}

pub fn mmio_r16(va: VirtAddr) -> u16 {
    MMIO_STATS.record_read();
    unsafe { ptr::read_volatile(va.as_ptr()) }
}

pub fn mmio_r32(va: VirtAddr) -> u32 {
    MMIO_STATS.record_read();
    unsafe { ptr::read_volatile(va.as_ptr()) }
}

pub fn mmio_r64(va: VirtAddr) -> u64 {
    MMIO_STATS.record_read();
    unsafe { ptr::read_volatile(va.as_ptr()) }
}

pub fn mmio_w8(va: VirtAddr, value: u8) {
    MMIO_STATS.record_write();
    unsafe { ptr::write_volatile(va.as_mut_ptr(), value) }
}

pub fn mmio_w16(va: VirtAddr, value: u16) {
    MMIO_STATS.record_write();
    unsafe { ptr::write_volatile(va.as_mut_ptr(), value) }
}

pub fn mmio_w32(va: VirtAddr, value: u32) {
    MMIO_STATS.record_write();
    unsafe { ptr::write_volatile(va.as_mut_ptr(), value) }
}

pub fn mmio_w64(va: VirtAddr, value: u64) {
    MMIO_STATS.record_write();
    unsafe { ptr::write_volatile(va.as_mut_ptr(), value) }
}

pub fn get_mapped_regions() -> alloc::vec::Vec<MmioRegion> {
    let manager = MMIO_MANAGER.lock();
    manager.regions.values().copied().collect()
}