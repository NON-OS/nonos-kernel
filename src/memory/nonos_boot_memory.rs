//! Boot Memory Management
//!
//! Enhanced memory mapping and initialization for N0N-OS kernel boot process

use alloc::{vec::Vec, collections::BTreeMap};
use core::ptr::NonNull;
use x86_64::{VirtAddr, PhysAddr, structures::paging::*};
use crate::memory::layout::*;

/// Boot memory information from bootloader
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BootMemoryInfo {
    pub magic: u64,
    pub abi_version: u16,
    pub hdr_size: u16,
    pub boot_flags: u32,
    pub capsule_base: u64,
    pub capsule_size: u64,
    pub capsule_hash: [u8; 32],
    pub memory_start: u64,
    pub memory_size: u64,
    pub entropy: [u8; 32],
    pub rtc_utc: [u8; 8],
    pub reserved: [u8; 8],
}

/// Memory region types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMemoryType {
    Available,
    Reserved,
    Kernel,
    Bootloader,
    Firmware,
    HardwareReserved,
    Defective,
}

/// Memory region descriptor
#[derive(Debug, Clone, Copy)]
pub struct BootMemoryRegion {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub region_type: BootMemoryType,
    pub attributes: u32,
}

impl BootMemoryRegion {
    pub fn size(&self) -> u64 {
        self.end.as_u64() - self.start.as_u64()
    }
    
    pub fn is_available(&self) -> bool {
        matches!(self.region_type, BootMemoryType::Available)
    }
    
    pub fn contains(&self, addr: PhysAddr) -> bool {
        addr >= self.start && addr < self.end
    }
}

/// Enhanced boot memory manager
pub struct BootMemoryManager {
    regions: Vec<BootMemoryRegion>,
    page_tables: Option<NonNull<PageTable>>,
    kernel_base: VirtAddr,
    kernel_size: u64,
    available_memory: u64,
    reserved_memory: u64,
    identity_mapped: bool,
}

impl BootMemoryManager {
    /// Create new boot memory manager
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            page_tables: None,
            kernel_base: VirtAddr::new(KERNEL_BASE),
            kernel_size: 0,
            available_memory: 0,
            reserved_memory: 0,
            identity_mapped: false,
        }
    }
    
    /// Initialize from bootloader handoff information
    pub fn initialize_from_handoff(&mut self, handoff_addr: u64) -> Result<(), &'static str> {
        if handoff_addr == 0 {
            return self.initialize_default_layout();
        }
        
        // Safely read handoff information
        let handoff_info = unsafe {
            let ptr = handoff_addr as *const BootMemoryInfo;
            if ptr.is_null() {
                return self.initialize_default_layout();
            }
            ptr.read()
        };
        
        // Validate magic and version
        if handoff_info.magic != 0x30424F534F4E4F4E || handoff_info.abi_version != 1 {
            crate::log_warn!("Invalid handoff magic or version, using defaults");
            return self.initialize_default_layout();
        }
        
        crate::log::logger::log_info!(
            "[boot_memory] Boot handoff: memory_start=0x{:x}, memory_size=0x{:x}",
            handoff_info.memory_start, handoff_info.memory_size
        );
        
        // Create memory regions from handoff info
        self.create_regions_from_handoff(&handoff_info)?;
        
        // Set up initial memory mapping
        self.setup_initial_mapping()?;
        
        Ok(())
    }
    
    /// Create memory regions from handoff information
    fn create_regions_from_handoff(&mut self, handoff: &BootMemoryInfo) -> Result<(), &'static str> {
        self.regions.clear();
        
        // Add low memory (0-1MB) as reserved
        self.add_region(
            PhysAddr::new(0),
            PhysAddr::new(0x100000),
            BootMemoryType::Reserved,
            0
        );
        
        // Add kernel region
        let kernel_start = PhysAddr::new(0x100000); // 1MB
        let kernel_end = PhysAddr::new(kernel_start.as_u64() + self.estimate_kernel_size());
        self.add_region(kernel_start, kernel_end, BootMemoryType::Kernel, 0);
        
        // Add bootloader capsule region if present
        if handoff.capsule_size > 0 {
            let capsule_start = PhysAddr::new(handoff.capsule_base);
            let capsule_end = PhysAddr::new(handoff.capsule_base + handoff.capsule_size);
            self.add_region(capsule_start, capsule_end, BootMemoryType::Bootloader, 0);
        }
        
        // Add main memory region
        if handoff.memory_size > 0 {
            let memory_start = PhysAddr::new(handoff.memory_start.max(kernel_end.as_u64()));
            let memory_end = PhysAddr::new(handoff.memory_start + handoff.memory_size);
            self.add_region(memory_start, memory_end, BootMemoryType::Available, 0);
            self.available_memory = memory_end.as_u64() - memory_start.as_u64();
        }
        
        // Add high memory regions
        self.add_high_memory_regions()?;
        
        // Sort regions by start address
        self.regions.sort_by_key(|r| r.start.as_u64());
        
        crate::log::logger::log_info!(
            "[boot_memory] Created {} memory regions, {} bytes available",
            self.regions.len(), self.available_memory
        );
        
        Ok(())
    }
    
    /// Initialize default memory layout when no handoff info available
    fn initialize_default_layout(&mut self) -> Result<(), &'static str> {
        crate::log::logger::log_info!("Initializing default memory layout");
        
        self.regions.clear();
        
        // Default memory layout for QEMU/standard systems
        self.add_region(
            PhysAddr::new(0),
            PhysAddr::new(0xA0000),
            BootMemoryType::Available,
            0
        );
        
        self.add_region(
            PhysAddr::new(0xA0000),
            PhysAddr::new(0x100000),
            BootMemoryType::Reserved,
            0
        );
        
        // Kernel area (1MB - 16MB)
        self.add_region(
            PhysAddr::new(0x100000),
            PhysAddr::new(0x1000000),
            BootMemoryType::Kernel,
            0
        );
        
        // Main memory (16MB - 128MB default)
        self.add_region(
            PhysAddr::new(0x1000000),
            PhysAddr::new(0x8000000),
            BootMemoryType::Available,
            0
        );
        
        self.available_memory = 0x7000000; // 112MB
        
        self.setup_initial_mapping()?;
        
        Ok(())
    }
    
    /// Add high memory regions (above 4GB)
    fn add_high_memory_regions(&mut self) -> Result<(), &'static str> {
        // Add typical reserved regions
        
        // PCI hole (3GB - 4GB)
        self.add_region(
            PhysAddr::new(0xC0000000),
            PhysAddr::new(0x100000000),
            BootMemoryType::HardwareReserved,
            0
        );
        
        // LAPIC default location
        self.add_region(
            PhysAddr::new(0xFEE00000),
            PhysAddr::new(0xFEE01000),
            BootMemoryType::HardwareReserved,
            0
        );
        
        // IOAPIC default location
        self.add_region(
            PhysAddr::new(0xFEC00000),
            PhysAddr::new(0xFEC01000),
            BootMemoryType::HardwareReserved,
            0
        );
        
        Ok(())
    }
    
    /// Add a memory region
    fn add_region(&mut self, start: PhysAddr, end: PhysAddr, region_type: BootMemoryType, attributes: u32) {
        if start >= end {
            return;
        }
        
        let region = BootMemoryRegion {
            start,
            end,
            region_type,
            attributes,
        };
        
        if region_type == BootMemoryType::Reserved || region_type == BootMemoryType::HardwareReserved {
            self.reserved_memory += region.size();
        }
        
        self.regions.push(region);
    }
    
    /// Estimate kernel size
    fn estimate_kernel_size(&self) -> u64 {
        // Estimate based on linker symbols
        unsafe {
            let kernel_start = &crate::memory::layout::__kernel_start as *const _ as u64;
            let kernel_end = &crate::memory::layout::__kernel_end as *const _ as u64;
            let size = kernel_end - kernel_start;
            
            // Round up to 2MB boundary and add some margin
            let aligned_size = align_up(size, HUGE_2M as u64);
            aligned_size + (4 * 1024 * 1024) // Add 4MB margin
        }
    }
    
    /// Set up initial memory mapping
    fn setup_initial_mapping(&mut self) -> Result<(), &'static str> {
        crate::log::logger::log_info!("Setting up initial memory mapping");
        
        // Create initial page tables
        self.create_initial_page_tables()?;
        
        // Map kernel sections
        self.map_kernel_sections()?;
        
        // Set up direct mapping
        self.setup_direct_mapping()?;
        
        // Map essential hardware regions
        self.map_hardware_regions()?;
        
        self.identity_mapped = true;
        
        crate::log::logger::log_info!("Initial memory mapping complete");
        
        Ok(())
    }
    
    /// Create initial page tables
    fn create_initial_page_tables(&mut self) -> Result<(), &'static str> {
        // Allocate page table in available memory
        let pml4_addr = self.allocate_page_aligned(PAGE_SIZE)?;
        
        // Zero the page table
        unsafe {
            let pml4_ptr = pml4_addr.as_u64() as *mut u8;
            for i in 0..PAGE_SIZE {
                *pml4_ptr.add(i) = 0;
            }
        }
        
        self.page_tables = NonNull::new(pml4_addr.as_u64() as *mut PageTable);
        
        crate::log::logger::log_info!(
            "[boot_memory] Created PML4 at 0x{:x}",
            pml4_addr.as_u64()
        );
        
        Ok(())
    }
    
    /// Map kernel sections with appropriate permissions
    fn map_kernel_sections(&mut self) -> Result<(), &'static str> {
        let sections = kernel_sections();
        
        for section in &sections {
            let start_phys = PhysAddr::new(section.start - KERNEL_BASE);
            let start_virt = VirtAddr::new(section.start);
            let size = section.size();
            
            let mut flags = PageTableFlags::PRESENT;
            if section.rw {
                flags |= PageTableFlags::WRITABLE;
            }
            if section.nx {
                flags |= PageTableFlags::NO_EXECUTE;
            }
            if section.global {
                flags |= PageTableFlags::GLOBAL;
            }
            
            self.map_memory_range(start_virt, start_phys, size, flags)?;
            
            crate::log::logger::log_info!(
                "[boot_memory] Mapped kernel section 0x{:x}-0x{:x} -> 0x{:x} ({:?})",
                section.start, section.end, start_phys.as_u64(), flags
            );
        }
        
        Ok(())
    }
    
    /// Set up direct mapping window
    fn setup_direct_mapping(&mut self) -> Result<(), &'static str> {
        let direct_map_size = DIRECTMAP_SIZE.min(self.available_memory);
        
        // Map first portion of physical memory to direct map window
        let phys_start = PhysAddr::new(0);
        let virt_start = VirtAddr::new(DIRECTMAP_BASE);
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::GLOBAL;
        
        self.map_memory_range(virt_start, phys_start, direct_map_size, flags)?;
        
        crate::log::logger::log_info!(
            "[boot_memory] Direct mapped 0x{:x} bytes at 0x{:x} -> 0x{:x}",
            direct_map_size, DIRECTMAP_BASE, 0
        );
        
        Ok(())
    }
    
    /// Map essential hardware regions
    fn map_hardware_regions(&mut self) -> Result<(), &'static str> {
        // Map VGA text buffer
        let vga_phys = PhysAddr::new(0xB8000);
        let vga_virt = VirtAddr::new(MMIO_BASE);
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | 
                   PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH;
        
        self.map_memory_range(vga_virt, vga_phys, PAGE_SIZE as u64, flags)?;
        
        // Map LAPIC
        let lapic_phys = PhysAddr::new(0xFEE00000);
        let lapic_virt = VirtAddr::new(MMIO_BASE + 0x1000);
        
        self.map_memory_range(lapic_virt, lapic_phys, PAGE_SIZE as u64, flags)?;
        
        crate::log::logger::log_info!("Mapped hardware regions");
        
        Ok(())
    }
    
    /// Map a range of memory
    fn map_memory_range(
        &mut self,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        size: u64,
        flags: PageTableFlags
    ) -> Result<(), &'static str> {
        if self.page_tables.is_none() {
            return Err("Page tables not initialized");
        }
        
        let page_count = (size + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64;
        
        for i in 0..page_count {
            let virt_addr = virt_start + (i * PAGE_SIZE as u64);
            let phys_addr = phys_start + (i * PAGE_SIZE as u64);
            
            // Simple direct mapping for now
            // In a full implementation, this would properly walk page tables
            self.map_single_page(virt_addr, phys_addr, flags)?;
        }
        
        Ok(())
    }
    
    /// Map a single page with real page table manipulation
    fn map_single_page(
        &mut self,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        flags: PageTableFlags
    ) -> Result<(), &'static str> {
        use x86_64::structures::paging::{Page, PhysFrame, Size4KiB, PageTable, PageTableIndex};
        
        // Get the page directory indices
        let page = Page::<Size4KiB>::containing_address(virt_addr);
        let frame = PhysFrame::<Size4KiB>::containing_address(phys_addr);
        
        // Get current page table from CR3 register
        let (current_l4_frame, _) = x86_64::registers::control::Cr3::read();
        let l4_table_phys = current_l4_frame.start_address();
        
        // Convert physical address to virtual address for kernel access
        // Assume kernel maps physical memory at offset 0xFFFF_8000_0000_0000
        let l4_table_virt = VirtAddr::new(l4_table_phys.as_u64() + 0xFFFF_8000_0000_0000);
        let l4_table = unsafe { &mut *(l4_table_virt.as_mut_ptr::<PageTable>()) };
        
        // Extract page table indices
        let l4_index = page.p4_index();
        let l3_index = page.p3_index();
        let l2_index = page.p2_index();
        let l1_index = page.p1_index();
        
        // Walk/create page table hierarchy
        
        // Level 4 -> Level 3
        let l3_table = if l4_table[l4_index].is_unused() {
            // Allocate new L3 table
            let l3_frame = self.allocate_frame()?;
            let l3_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
            l4_table[l4_index].set_frame(l3_frame, l3_flags);
            
            // Clear the new table
            let l3_virt = VirtAddr::new(l3_frame.start_address().as_u64() + 0xFFFF_8000_0000_0000);
            let l3_table = unsafe { &mut *(l3_virt.as_mut_ptr::<PageTable>()) };
            l3_table.zero();
            l3_table
        } else {
            let l3_phys = l4_table[l4_index].frame().unwrap().start_address();
            let l3_virt = VirtAddr::new(l3_phys.as_u64() + 0xFFFF_8000_0000_0000);
            unsafe { &mut *(l3_virt.as_mut_ptr::<PageTable>()) }
        };
        
        // Level 3 -> Level 2  
        let l2_table = if l3_table[l3_index].is_unused() {
            let l2_frame = self.allocate_frame()?;
            let l2_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
            l3_table[l3_index].set_frame(l2_frame, l2_flags);
            
            let l2_virt = VirtAddr::new(l2_frame.start_address().as_u64() + 0xFFFF_8000_0000_0000);
            let l2_table = unsafe { &mut *(l2_virt.as_mut_ptr::<PageTable>()) };
            l2_table.zero();
            l2_table
        } else {
            let l2_phys = l3_table[l3_index].frame().unwrap().start_address();
            let l2_virt = VirtAddr::new(l2_phys.as_u64() + 0xFFFF_8000_0000_0000);
            unsafe { &mut *(l2_virt.as_mut_ptr::<PageTable>()) }
        };
        
        // Level 2 -> Level 1
        let l1_table = if l2_table[l2_index].is_unused() {
            let l1_frame = self.allocate_frame()?;
            let l1_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
            l2_table[l2_index].set_frame(l1_frame, l1_flags);
            
            let l1_virt = VirtAddr::new(l1_frame.start_address().as_u64() + 0xFFFF_8000_0000_0000);
            let l1_table = unsafe { &mut *(l1_virt.as_mut_ptr::<PageTable>()) };
            l1_table.zero();
            l1_table
        } else {
            let l1_phys = l2_table[l2_index].frame().unwrap().start_address();
            let l1_virt = VirtAddr::new(l1_phys.as_u64() + 0xFFFF_8000_0000_0000);
            unsafe { &mut *(l1_virt.as_mut_ptr::<PageTable>()) }
        };
        
        // Map the final page
        if !l1_table[l1_index].is_unused() {
            return Err("Page already mapped");
        }
        
        l1_table[l1_index].set_frame(frame, flags);
        
        // Flush TLB for this page
        unsafe {
            x86_64::instructions::tlb::flush(virt_addr);
        }
        
        crate::log_debug!("Mapped page 0x{:x} -> 0x{:x} with flags {:?}",
            virt_addr.as_u64(), phys_addr.as_u64(), flags);
        
        Ok(())
    }
    
    /// Allocate a physical frame for page tables
    fn allocate_frame(&mut self) -> Result<PhysFrame<Size4KiB>, &'static str> {
        // Find a free page from our memory regions
        for region in &mut self.memory_regions {
            if region.region_type == BootMemoryType::Usable && region.used_pages < region.total_pages {
                let frame_addr = region.base_address + (region.used_pages as u64 * 4096);
                region.used_pages += 1;
                
                // Zero the frame
                let frame_virt = VirtAddr::new(frame_addr + 0xFFFF_8000_0000_0000);
                unsafe {
                    core::ptr::write_bytes(frame_virt.as_mut_ptr::<u8>(), 0, 4096);
                }
                
                return Ok(PhysFrame::containing_address(PhysAddr::new(frame_addr)));
            }
        }
        Err("Out of physical memory")
    }
    
    /// Allocate page-aligned memory
    fn allocate_page_aligned(&mut self, size: usize) -> Result<PhysAddr, &'static str> {
        let aligned_size = align_up(size as u64, PAGE_SIZE as u64);
        
        // Find available region with enough space
        for region in &mut self.regions {
            if region.is_available() && region.size() >= aligned_size {
                let addr = PhysAddr::new(align_up(region.start.as_u64(), PAGE_SIZE as u64));
                
                // Update region to reflect allocation
                if addr.as_u64() + aligned_size < region.end.as_u64() {
                    region.start = PhysAddr::new(addr.as_u64() + aligned_size);
                    return Ok(addr);
                }
            }
        }
        
        Err("Out of memory")
    }
    
    /// Get memory statistics
    pub fn get_stats(&self) -> BootMemoryStats {
        let mut stats = BootMemoryStats {
            total_regions: self.regions.len(),
            available_memory: 0,
            reserved_memory: 0,
            kernel_memory: 0,
            bootloader_memory: 0,
            hardware_memory: 0,
            total_memory: 0,
        };
        
        for region in &self.regions {
            let size = region.size();
            stats.total_memory += size;
            
            match region.region_type {
                BootMemoryType::Available => stats.available_memory += size,
                BootMemoryType::Reserved => stats.reserved_memory += size,
                BootMemoryType::Kernel => stats.kernel_memory += size,
                BootMemoryType::Bootloader => stats.bootloader_memory += size,
                BootMemoryType::HardwareReserved => stats.hardware_memory += size,
                _ => stats.reserved_memory += size,
            }
        }
        
        stats
    }
    
    /// Dump memory map for debugging
    pub fn dump_memory_map(&self) {
        crate::log::logger::log_info!("Memory Map:");
        
        for (i, region) in self.regions.iter().enumerate() {
            crate::log::logger::log_info!(
                "[boot_memory]   {:2}: 0x{:016x}-0x{:016x} {:>8} KB {:?}",
                i,
                region.start.as_u64(),
                region.end.as_u64(),
                region.size() / 1024,
                region.region_type
            );
        }
        
        let stats = self.get_stats();
        crate::log::logger::log_info!(
            "[boot_memory] Memory Stats: Total={} MB, Available={} MB, Reserved={} MB",
            stats.total_memory / (1024 * 1024),
            stats.available_memory / (1024 * 1024),
            stats.reserved_memory / (1024 * 1024)
        );
    }
    
    /// Enable paging with current page tables
    pub fn enable_paging(&self) -> Result<(), &'static str> {
        if let Some(pml4) = self.page_tables {
            unsafe {
                // Load CR3 with PML4 address
                core::arch::asm!(
                    "mov cr3, {}",
                    in(reg) pml4.as_ptr() as u64,
                    options(nostack, preserves_flags)
                );
                
                // Enable paging in CR0
                let mut cr0: u64;
                core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nostack, preserves_flags));
                cr0 |= 1 << 31; // PG bit
                core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
            }
            
            crate::log::logger::log_info!("Paging enabled successfully");
            Ok(())
        } else {
            Err("No page tables available")
        }
    }
    
    /// Get available memory regions
    pub fn get_available_regions(&self) -> Vec<BootMemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.is_available())
            .cloned()
            .collect()
    }
    
    /// Find region containing address
    pub fn find_region(&self, addr: PhysAddr) -> Option<&BootMemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }
}

/// Memory statistics
#[derive(Debug, Clone)]
pub struct BootMemoryStats {
    pub total_regions: usize,
    pub available_memory: u64,
    pub reserved_memory: u64,
    pub kernel_memory: u64,
    pub bootloader_memory: u64,
    pub hardware_memory: u64,
    pub total_memory: u64,
}

/// Global boot memory manager
use spin::Mutex;
static BOOT_MEMORY_MANAGER: Mutex<Option<BootMemoryManager>> = Mutex::new(None);

/// Initialize boot memory manager
pub fn init_boot_memory(handoff_addr: u64) -> Result<(), &'static str> {
    let mut manager_guard = BOOT_MEMORY_MANAGER.lock();
    if manager_guard.is_some() {
        return Err("Boot memory manager already initialized");
    }
    
    let mut manager = BootMemoryManager::new();
    manager.initialize_from_handoff(handoff_addr)?;
    
    // Dump memory map for debugging
    manager.dump_memory_map();
    
    *manager_guard = Some(manager);
    
    crate::log::logger::log_info!("Boot memory manager initialized successfully");
    Ok(())
}

/// Get global boot memory manager
pub fn get_boot_memory_manager() -> Option<&'static Mutex<Option<BootMemoryManager>>> {
    Some(&BOOT_MEMORY_MANAGER)
}

/// Get memory statistics
pub fn get_memory_stats() -> Option<BootMemoryStats> {
    let manager_guard = BOOT_MEMORY_MANAGER.lock();
    manager_guard.as_ref().map(|m| m.get_stats())
}

/// Allocate physical pages during boot
pub fn allocate_boot_pages(count: usize) -> Result<PhysAddr, &'static str> {
    let mut manager_guard = BOOT_MEMORY_MANAGER.lock();
    if let Some(ref mut manager) = *manager_guard {
        manager.allocate_page_aligned(count * PAGE_SIZE)
    } else {
        Err("Boot memory manager not initialized")
    }
}

/// Enable memory protection
pub fn enable_memory_protection() -> Result<(), &'static str> {
    let manager_guard = BOOT_MEMORY_MANAGER.lock();
    if let Some(ref manager) = *manager_guard {
        manager.enable_paging()
    } else {
        Err("Boot memory manager not initialized")
    }
}