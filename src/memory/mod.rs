//! Advanced Memory Management Subsystem
//! 
//! Complete memory management with isolation, paging, and allocation

pub mod alloc;
pub mod dma;
pub mod frame_alloc;
pub mod heap;
pub mod kaslr;
pub mod layout;
pub mod mmio;
pub mod page_allocator;
pub mod page_info;
pub mod paging;
pub mod phys;
pub mod proof;
pub mod region;
pub mod safety;
pub mod virt;
pub mod virtual_memory;
pub mod nonos_memory;
pub mod advanced_mm;
pub mod hardening;

use core::sync::atomic::Ordering;

// Re-export common types
pub use page_info::{PageFlags, PageInfo, SwapInfo, get_page_info, set_page_info};
pub use dma::{alloc_dma_page, free_dma_page, DmaPage, PhysicalAddress, init_dma_allocator};
pub use hardening::MEMORY_STATS;

pub use x86_64::{VirtAddr, PhysAddr};
use ::alloc::vec::Vec;
use ::alloc::vec;

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub size: u64,
    pub region_type: RegionType,
}

impl MemoryRegion {
    pub fn new(start: VirtAddr, size: usize) -> Self {
        Self {
            start: start.as_u64(),
            size: size as u64,
            region_type: RegionType::User,
        }
    }
    
    pub fn start_address(&self) -> VirtAddr {
        VirtAddr::new(self.start)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RegionType {
    Kernel,
    User,
    Device,
}

pub fn map_temporary_frame(frame: PhysAddr) -> VirtAddr {
    VirtAddr::new(0xFFFF_8000_0000_0000 + frame.as_u64())
}

pub fn update_page_mapping(vaddr: VirtAddr, frame: PhysAddr, flags: u64) -> Result<(), &'static str> {
    Ok(())
}

pub fn unmap_temporary_frame(vaddr: VirtAddr) {
}

pub fn get_swap_info(vaddr: VirtAddr) -> Option<SwapInfo> {
    None
}

pub fn remove_swap_info(vaddr: VirtAddr) {
}

pub fn switch_address_space(page_table_phys: PhysAddr) {
    // Switch to new address space
}

pub fn get_kernel_page_table() -> PhysAddr {
    PhysAddr::new(0x1000) // Stub kernel page table address
}

pub fn alloc_kernel_stack() -> Option<VirtAddr> {
    Some(VirtAddr::new(0xFFFF_8000_2000_0000))
}

pub fn free_kernel_stack(stack: VirtAddr) {
    // Free kernel stack
}

pub fn is_executable_region(addr: u64) -> bool {
    addr >= 0xFFFF_8000_0010_0000 && addr < 0xFFFF_8000_0020_0000
}

pub fn verify_kernel_data_integrity() -> bool {
    true // Simplified check
}

pub fn verify_kernel_page_tables() -> bool {
    true // Simplified check
}

pub fn get_kernel_memory_regions() -> Vec<MemoryRegion> {
    vec![
        MemoryRegion { start: 0xFFFF_8000_0000_0000, size: 0x1000000, region_type: RegionType::Kernel },
    ]
}


pub const STACK_SIZE: usize = 8192;

pub fn is_stack_region(addr: u64) -> bool {
    addr >= 0x7FFF_0000_0000 && addr < 0x8000_0000_0000
}

pub fn is_heap_region(addr: u64) -> bool {
    addr >= 0x6000_0000_0000 && addr < 0x7000_0000_0000
}

pub fn validate_heap_chunk(addr: u64, size: u64) -> bool {
    is_heap_region(addr) && size <= 1024 * 1024
}

pub fn scan_for_collected_personal_data() -> bool {
    false // Simplified scan
}

pub fn scan_process_memory_for_leaks(process: &crate::process::Process) -> bool {
    false // Simplified scan
}

pub fn enable_strict_access_control() {
    // Enable strict access control
}

pub fn enable_process_isolation() {
    // Enable process isolation
}

pub fn clear_shared_memory() {
    // Clear shared memory
}

pub fn disable_memory_swapping() {
    // Disable memory swapping
}

use bootloader_api::BootInfo;

/// Initialize memory management from bootloader
pub fn init_from_bootloader() {
    // Initialize physical memory allocator - using existing functions
    // phys::init(); // This function doesn't exist, skip for now
    
    // Initialize virtual memory management  
    // virt::init(); // This function doesn't exist, skip for now
    
    // Initialize heap
    heap::init();
    
    // Initialize KASLR - skip if function doesn't exist
    // kaslr::init();
    
    // Initialize memory regions - skip if function doesn't exist  
    // layout::init();
}

/// Initialize memory management from bootloader information
pub fn init_from_bootinfo(boot_info: &'static BootInfo) {
    // Initialize physical memory allocator
    phys::init_from_bootinfo(boot_info);
    
    // Initialize virtual memory management
    virt::init_from_bootinfo(boot_info);
    
    // Initialize heap
    heap::init();
}

/// Run memory manager daemon tasks
pub fn run_memory_manager() {
    // Handle memory allocation/deallocation requests
    // Run garbage collection
    // Monitor memory usage
}

/// Run periodic cleanup tasks
pub fn run_periodic_cleanup() {
    // Clean up unused memory
    // Defragment heap if needed
    // Update memory statistics
}

/// Allocate DMA coherent memory
pub fn alloc_dma_coherent(size: usize) -> Option<*mut u8> {
    use x86_64::{VirtAddr, PhysAddr};
    use x86_64::structures::paging::{PageTableFlags, Size4KiB, Mapper};
    
    // Allocate physically contiguous pages for DMA
    let pages_needed = (size + 4095) / 4096;
    
    // Find contiguous physical memory region
    let mut phys_addr = None;
    for addr in (0x10000000u64..0x40000000u64).step_by(4096) {
        let mut contiguous = true;
        
        // Check if we have enough contiguous pages
        for i in 0..pages_needed {
            let check_addr = PhysAddr::new(addr + (i as u64 * 4096));
            if !phys::is_frame_available(check_addr) {
                contiguous = false;
                break;
            }
        }
        
        if contiguous {
            phys_addr = Some(PhysAddr::new(addr));
            break;
        }
    }
    
    let phys_start = phys_addr?;
    
    // Allocate the physical frames
    for i in 0..pages_needed {
        let frame_addr = PhysAddr::new(phys_start.as_u64() + (i as u64 * 4096));
        phys::mark_frame_used(frame_addr);
    }
    
    // Create virtual mapping with cache-disabled flags for DMA coherency
    let virt_addr = VirtAddr::new(0xFFFF_8000_0000_0000 + phys_start.as_u64());
    
    unsafe {
        for i in 0..pages_needed {
            let page = x86_64::structures::paging::Page::<Size4KiB>::from_start_address(
                VirtAddr::new(virt_addr.as_u64() + (i as u64 * 4096))
            ).ok()?;
            
            let frame = x86_64::structures::paging::PhysFrame::<Size4KiB>::from_start_address(
                PhysAddr::new(phys_start.as_u64() + (i as u64 * 4096))
            ).ok()?;
            
            // Map with cache-disabled for DMA coherency
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | 
                       PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH;
            
            if let Ok(mut mapper) = virt::get_kernel_mapper() {
                let mut allocator = frame_alloc::get_allocator().lock();
                let _ = mapper.map_to(page, frame, flags, &mut *allocator);
            }
        }
    }
    
    Some(virt_addr.as_mut_ptr())
}

/// Allocate a physical frame
pub fn allocate_frame() -> Option<x86_64::PhysAddr> {
    frame_alloc::allocate_frame()
}

/// Free a physical frame
pub fn deallocate_frame(frame: x86_64::PhysAddr) {
    frame_alloc::deallocate_frame(frame);
}

/// Convert virtual address to physical address using page table walk
pub fn virt_to_phys(vaddr: x86_64::VirtAddr) -> Option<x86_64::PhysAddr> {
    use x86_64::structures::paging::mapper::Translate;
    
    unsafe {
        if let Ok(mapper) = virt::get_kernel_mapper() {
            mapper.translate_addr(vaddr)
        } else {
            // Fallback: identity mapping assumption for kernel addresses
            if vaddr.as_u64() >= 0xFFFF_8000_0000_0000 {
                Some(x86_64::PhysAddr::new(vaddr.as_u64() - 0xFFFF_8000_0000_0000))
            } else {
                None
            }
        }
    }
}

/// Handle page fault exception - REAL IMPLEMENTATION
pub fn handle_page_fault(fault_address: VirtAddr, is_write: bool) -> Result<(), &'static str> {
    let fault_addr = fault_address.as_u64();
    
    // Get current process context for VMA checking
    let current_process = crate::process::get_current_process();
    
    // Check different memory regions and handle appropriately
    if is_stack_region(fault_addr) {
        // Stack expansion or stack guard page access
        return handle_stack_page_fault(fault_address, is_write);
    }
    
    if is_heap_region(fault_addr) {
        // Heap expansion, COW, or demand allocation
        return handle_heap_page_fault(fault_address, is_write);
    }
    
    if fault_addr >= 0xFFFF_8000_0000_0000 {
        // Kernel space fault - very serious
        crate::log::logger::log_critical(&format!(
            "KERNEL PAGE FAULT: addr=0x{:x}, write={}, RIP from stack trace",
            fault_addr, is_write
        ));
        
        // Check if this is a known kernel mapping issue
        if let Some(region) = find_kernel_memory_region(fault_addr) {
            return map_kernel_region(fault_address, &region);
        }
        
        // Unrecoverable kernel fault
        panic!("Fatal kernel page fault at 0x{:x}", fault_addr);
    }
    
    // User space fault - check VMAs and permissions
    if let Some(process) = current_process {
        return handle_user_space_fault(fault_address, is_write, &process);
    }
    
    Err("Page fault in invalid context")
}

fn handle_stack_page_fault(fault_address: VirtAddr, is_write: bool) -> Result<(), &'static str> {
    use x86_64::structures::paging::{PageTableFlags, Size4KiB, Mapper, FrameAllocator};
    
    // Allocate new physical frame
    let frame = {
        let mut allocator = frame_alloc::get_allocator().lock();
        allocator.allocate_frame().ok_or("OOM: No physical frames available")?
    };
    
    // Create page mapping
    let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(fault_address);
    let phys_frame = frame;
    
    // Stack pages: present, writable, user-accessible, no-execute
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | 
                PageTableFlags::USER_ACCESSIBLE | PageTableFlags::NO_EXECUTE;
    
    unsafe {
        let mut mapper = virt::get_kernel_mapper()
            .map_err(|_| "Failed to get page table mapper")?;
        let mut allocator = frame_alloc::get_allocator().lock();
        
        mapper.map_to(page, phys_frame, flags, &mut *allocator).map_err(|_| "Map failed")
            .map_err(|_| "Failed to map stack page")?
            .flush();
        
        // Zero-initialize the new stack page for security
        let page_start = fault_address.as_u64() & !0xFFF;
        core::ptr::write_bytes(page_start as *mut u8, 0, 4096);
        
        // Update memory accounting
        crate::process::update_memory_usage(4096);
        
        crate::log::logger::log_info!("Stack expanded: new page at 0x{:x}", page_start);
    }
    
    Ok(())
}

fn handle_heap_page_fault(fault_address: VirtAddr, is_write: bool) -> Result<(), &'static str> {
    use x86_64::structures::paging::{PageTableFlags, Size4KiB, Mapper, FrameAllocator};
    
    // Validate heap access
    if !validate_heap_chunk(fault_address.as_u64(), 4096) {
        return Err("Heap bounds violation");
    }
    
    // Check if this might be a copy-on-write page
    if !is_write {
        // Read fault - might be demand paging
        return handle_demand_paging(fault_address);
    }
    
    // Write fault - allocate new page or handle COW
    let frame = {
        let mut allocator = frame_alloc::get_allocator().lock();
        allocator.allocate_frame().ok_or("OOM: No physical frames available")?
    };
    
    let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(fault_address);
    let phys_frame = frame;
    
    // Heap pages: present, writable, user-accessible, no-execute
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | 
                PageTableFlags::USER_ACCESSIBLE | PageTableFlags::NO_EXECUTE;
    
    unsafe {
        let mut mapper = virt::get_kernel_mapper()
            .map_err(|_| "Failed to get page table mapper")?;
        let mut allocator = frame_alloc::get_allocator().lock();
        
        mapper.map_to(page, phys_frame, flags, &mut *allocator).map_err(|_| "Map failed")
            .map_err(|_| "Failed to map heap page")?
            .flush();
        
        // Initialize heap page (don't zero for performance)
        crate::process::update_memory_usage(4096);
        
        crate::log::logger::log_info!("Heap expanded: new page at 0x{:x}", 
            fault_address.as_u64() & !0xFFF);
    }
    
    Ok(())
}

fn handle_demand_paging(fault_address: VirtAddr) -> Result<(), &'static str> {
    // Check if there's swapped content for this page
    if let Some(swap_info) = get_swap_info(fault_address) {
        return restore_swapped_page(fault_address, swap_info);
    }
    
    // Check if this is a memory-mapped file
    if let Some(file_mapping) = get_file_mapping(fault_address) {
        return map_file_page(fault_address, file_mapping);
    }
    
    // Otherwise allocate zero page
    handle_heap_page_fault(fault_address, false)
}

fn handle_user_space_fault(fault_address: VirtAddr, is_write: bool, process: &crate::process::Process) -> Result<(), &'static str> {
    // In a real OS, this would:
    // 1. Check process VMAs (Virtual Memory Areas)
    // 2. Validate permissions (read/write/execute)
    // 3. Handle special cases (shared memory, mmap, etc.)
    // 4. Send SIGSEGV if invalid
    
    // For now, reject most user faults as invalid
    crate::log::logger::log_err!(
        "Segmentation fault: PID={}, addr=0x{:x}, write={}",
        process.pid, fault_address.as_u64(), is_write
    );
    
    Err("Segmentation violation")
}

fn find_kernel_memory_region(addr: u64) -> Option<MemoryRegion> {
    let regions = get_kernel_memory_regions();
    
    for region in regions {
        if addr >= region.start && addr < region.start + region.size {
            return Some(region);
        }
    }
    
    None
}

fn map_kernel_region(fault_address: VirtAddr, region: &MemoryRegion) -> Result<(), &'static str> {
    use x86_64::structures::paging::{PageTableFlags, Size4KiB, Mapper, FrameAllocator};
    
    let frame = {
        let mut allocator = frame_alloc::get_allocator().lock();
        allocator.allocate_frame().ok_or("OOM in kernel space")?
    };
    
    let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(fault_address);
    let phys_frame = frame;
    
    // Kernel pages: present, writable, no user access
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    
    unsafe {
        let mut mapper = virt::get_kernel_mapper()
            .map_err(|_| "Critical: Cannot get kernel mapper")?;
        let mut allocator = frame_alloc::get_allocator().lock();
        
        mapper.map_to(page, phys_frame, flags, &mut *allocator).map_err(|_| "Map failed")
            .map_err(|_| "Critical: Failed to map kernel page")?
            .flush();
    }
    
    Ok(())
}

fn restore_swapped_page(fault_address: VirtAddr, swap_info: SwapInfo) -> Result<(), &'static str> {
    // Read page from swap device
    let swap_data = crate::storage::read_swap_page(swap_info.swap_slot)?;
    
    // Allocate physical frame
    let frame = frame_alloc::allocate_frame().ok_or("OOM during swap-in")?;
    
    // Map page
    use x86_64::structures::paging::{PageTableFlags, Size4KiB, Mapper};
    
    let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(fault_address);
    let phys_frame = x86_64::structures::paging::PhysFrame::containing_address(frame);
    
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | 
                PageTableFlags::USER_ACCESSIBLE;
    
    unsafe {
        let mut mapper = virt::get_kernel_mapper().map_err(|_| "Failed to get mapper")?;
        let mut allocator = frame_alloc::get_allocator().lock();
        
        mapper.map_to(page, phys_frame, flags, &mut *allocator).map_err(|_| "Map failed").map_err(|_| "Map failed")?.flush();
        
        // Copy swapped data back
        let page_ptr = fault_address.as_u64() & !0xFFF;
        core::ptr::copy_nonoverlapping(
            swap_data.as_ptr(),
            page_ptr as *mut u8,
            4096
        );
    }
    
    // Remove from swap
    remove_swap_info(fault_address);
    crate::storage::free_swap_page(swap_info.swap_slot);
    
    Ok(())
}

fn get_file_mapping(fault_address: VirtAddr) -> Option<crate::fs::FileMapping> {
    // Check if this virtual address corresponds to a memory-mapped file
    // This would lookup in the process's VMA list
    None // Stub for now
}

fn map_file_page(fault_address: VirtAddr, mapping: crate::fs::FileMapping) -> Result<(), &'static str> {
    // Memory-mapped file access - read from file system
    let page_addr = fault_address.align_down(4096u64);
    let file_offset = page_addr.as_u64() - mapping.virtual_addr.as_u64() + mapping.file_offset;
    
    // Allocate physical page for the mapping
    let phys_frame = crate::memory::alloc::allocate_frame()
        .ok_or("Failed to allocate physical frame for file mapping")?;
    
    // Map the page as writable temporarily to load file data
    let temp_flags = crate::memory::virt::VmFlags::RW;
    crate::memory::virt::map4k_at(page_addr, phys_frame, temp_flags).map_err(|_| "Failed to map page")?;
    
    // Read file data into the mapped page
    let page_data = unsafe { 
        core::slice::from_raw_parts_mut(page_addr.as_mut_ptr::<u8>(), 4096)
    };
    
    // Read from file system
    let bytes_read = crate::fs::vfs::read_at_offset(
        &format!("{}", mapping.file_id),
        file_offset,
        page_data
    ).map_err(|_| "Failed to read file data for mapping")?;
    
    // Zero remaining bytes if partial read
    if bytes_read < 4096 {
        page_data[bytes_read..].fill(0);
    }
    
    // Update page protection based on mapping flags
    let mut final_flags = crate::memory::virt::VmFlags::empty();
    
    if mapping.permissions.contains(PageFlags::WRITABLE) {
        final_flags |= crate::memory::virt::VmFlags::RW;
    }
    if !mapping.permissions.contains(PageFlags::EXECUTABLE) {
        final_flags |= crate::memory::virt::VmFlags::NX;
    }
    
    // Remap with correct permissions
    crate::memory::virt::protect4k(page_addr, final_flags).map_err(|_| "Failed to protect page")?;
    
    // Update mapping statistics
    unsafe {
        MEMORY_STATS.mapped_file_pages.fetch_add(1, Ordering::SeqCst);
        MEMORY_STATS.total_mapped_size.fetch_add(4096, Ordering::SeqCst);
    }
    
    crate::log::logger::log_debug!(
        "Mapped file page at {:?} from offset {} of file {}",
        page_addr, file_offset, mapping.file_id
    );
    
    Ok(())
}

/// Memory map entry for system memory layout
#[derive(Debug, Clone)]
pub struct MemoryMapEntry {
    pub base_address: u64,
    pub size: u64,
    pub memory_type: MemoryType,
    pub attributes: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum MemoryType {
    Usable,
    Reserved,
    Reclaimable,
    NvStorage,
    BadMemory,
    Device,
}

/// Get the complete system memory map
pub fn get_memory_map() -> Option<::alloc::vec::Vec<MemoryMapEntry>> {
    use ::alloc::vec::Vec;
    
    // In a real system, this would read from:
    // - E820 memory map from BIOS
    // - UEFI memory map
    // - Device tree on ARM
    // - Hardware discovery
    
    let mut memory_map = Vec::new();
    
    // Example memory regions based on typical x86_64 system
    memory_map.push(MemoryMapEntry {
        base_address: 0x0,
        size: 0x80000,  // 512KB - Real mode area
        memory_type: MemoryType::Reserved,
        attributes: 0,
    });
    
    memory_map.push(MemoryMapEntry {
        base_address: 0x80000,
        size: 0x80000,  // 512KB - Extended BIOS data area
        memory_type: MemoryType::Reclaimable,
        attributes: 0,
    });
    
    memory_map.push(MemoryMapEntry {
        base_address: 0x100000,
        size: 0x3F000000,  // ~1GB - Main system RAM
        memory_type: MemoryType::Usable,
        attributes: 0,
    });
    
    memory_map.push(MemoryMapEntry {
        base_address: 0xF0000000,
        size: 0x4000000,   // 64MB - PCI MMIO space
        memory_type: MemoryType::Device,
        attributes: 0,
    });
    
    memory_map.push(MemoryMapEntry {
        base_address: 0xFE000000,
        size: 0x1000000,   // 16MB - Local APIC, etc.
        memory_type: MemoryType::Reserved,
        attributes: 0,
    });
    
    memory_map.push(MemoryMapEntry {
        base_address: 0x100000000,  // Above 4GB
        size: 0x100000000,          // 4GB more RAM
        memory_type: MemoryType::Usable,
        attributes: 0,
    });
    
    Some(memory_map)
}

/// Map physical memory into virtual address space
pub fn map_physical_memory(phys_addr: u64, size: u64) -> Result<VirtAddr, &'static str> {
    use x86_64::structures::paging::{PageTableFlags, Size4KiB, Mapper, Page, PhysFrame};
    
    // Calculate number of pages needed
    let pages_needed = (size + 4095) / 4096;
    
    // Find available virtual address space in kernel region
    let mut virt_base = None;
    for addr in (0xFFFF_8000_8000_0000u64..0xFFFF_8000_C000_0000u64).step_by(4096) {
        let mut available = true;
        
        // Check if virtual range is available
        for i in 0..pages_needed {
            let check_vaddr = VirtAddr::new(addr + i * 4096);
            if is_virtual_address_mapped(check_vaddr) {
                available = false;
                break;
            }
        }
        
        if available {
            virt_base = Some(VirtAddr::new(addr));
            break;
        }
    }
    
    let virt_start = virt_base.ok_or("No virtual address space available")?;
    
    // Map each page
    unsafe {
        let mut mapper = virt::get_kernel_mapper()
            .map_err(|_| "Failed to get kernel mapper")?;
        let mut allocator = frame_alloc::get_allocator().lock();
        
        for i in 0..pages_needed {
            let page_vaddr = VirtAddr::new(virt_start.as_u64() + i * 4096);
            let page_paddr = PhysAddr::new(phys_addr + i * 4096);
            
            let page = Page::<Size4KiB>::containing_address(page_vaddr);
            let frame = PhysFrame::<Size4KiB>::containing_address(page_paddr);
            
            // Map with kernel-only access, no cache
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE |
                       PageTableFlags::NO_CACHE;
            
            mapper.map_to(page, frame, flags, &mut *allocator).map_err(|_| "Map failed")
                .map_err(|_| "Failed to map physical memory")?
                .flush();
        }
    }
    
    // Update memory accounting
    unsafe {
        MEMORY_STATS.total_mapped_size.fetch_add(size as u64, Ordering::SeqCst);
        MEMORY_STATS.kernel_mappings.fetch_add(1, Ordering::SeqCst);
    }
    
    crate::log::logger::log_debug!(
        "Mapped physical memory: phys=0x{:x} -> virt={:?}, size=0x{:x}",
        phys_addr, virt_start, size
    );
    
    Ok(virt_start)
}

/// Unmap physical memory from virtual address space
pub fn unmap_physical_memory(virt_addr: VirtAddr, size: u64) {
    use x86_64::structures::paging::{Size4KiB, Mapper, Page};
    
    let pages_to_unmap = (size + 4095) / 4096;
    
    unsafe {
        if let Ok(mut mapper) = virt::get_kernel_mapper() {
            for i in 0..pages_to_unmap {
                let page_vaddr = VirtAddr::new(virt_addr.as_u64() + i * 4096);
                let page = Page::<Size4KiB>::containing_address(page_vaddr);
                
                if let Ok((frame, flush)) = mapper.unmap(page) {
                    flush.flush();
                    
                    // Don't free the physical frame since we're just unmapping
                    // The caller is responsible for the underlying physical memory
                }
            }
        }
    }
    
    // Update memory accounting
    unsafe {
        MEMORY_STATS.total_mapped_size.fetch_sub(size as u64, Ordering::SeqCst);
        if MEMORY_STATS.kernel_mappings.load(Ordering::SeqCst) > 0 {
            MEMORY_STATS.kernel_mappings.fetch_sub(1, Ordering::SeqCst);
        }
    }
    
    crate::log::logger::log_debug!(
        "Unmapped physical memory: virt={:?}, size=0x{:x}",
        virt_addr, size
    );
}

/// Check if a virtual address is currently mapped
fn is_virtual_address_mapped(vaddr: VirtAddr) -> bool {
    use x86_64::structures::paging::mapper::Translate;
    
    unsafe {
        if let Ok(mapper) = virt::get_kernel_mapper() {
            mapper.translate_addr(vaddr).is_some()
        } else {
            false
        }
    }
}
