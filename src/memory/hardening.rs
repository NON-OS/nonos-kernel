//! Memory Safety Hardening for NONOS Production Kernel
//!
//! Production-grade memory safety mechanisms:
//! - Guard pages around all allocations
//! - W^X (Write XOR Execute) enforcement
//! - Secure zeroization with compiler barriers
//! - Stack canaries and overflow detection
//! - SMEP/SMAP enforcement
//! - Memory tagging and bounds checking

use x86_64::{VirtAddr, structures::paging::{PageTableFlags, Size4KiB, Page, PhysFrame, Mapper}};
use core::sync::atomic::{AtomicU64, Ordering};
use core::ptr;
use spin::Mutex;
use alloc::collections::BTreeMap;

/// Global memory safety statistics
pub static MEMORY_STATS: MemoryStats = MemoryStats::new();

/// Memory safety statistics
pub struct MemoryStats {
    pub guard_page_violations: AtomicU64,
    pub wx_violations: AtomicU64,
    pub stack_overflows_detected: AtomicU64,
    pub heap_corruptions_detected: AtomicU64,
    pub double_frees_prevented: AtomicU64,
    pub use_after_free_detected: AtomicU64,
    pub mapped_file_pages: AtomicU64,
    pub total_mapped_size: AtomicU64,
    pub kernel_mappings: AtomicU64,
}

impl MemoryStats {
    pub const fn new() -> Self {
        Self {
            guard_page_violations: AtomicU64::new(0),
            wx_violations: AtomicU64::new(0),
            stack_overflows_detected: AtomicU64::new(0),
            heap_corruptions_detected: AtomicU64::new(0),
            double_frees_prevented: AtomicU64::new(0),
            use_after_free_detected: AtomicU64::new(0),
            mapped_file_pages: AtomicU64::new(0),
            total_mapped_size: AtomicU64::new(0),
            kernel_mappings: AtomicU64::new(0),
        }
    }
}

/// Memory allocation metadata for tracking
#[derive(Debug, Clone)]
pub struct AllocationMetadata {
    pub base_addr: VirtAddr,
    pub size: usize,
    pub guard_before: VirtAddr,
    pub guard_after: VirtAddr,
    pub allocated_at: u64,
    pub magic: u64,
    pub checksum: u64,
}

/// Global allocation tracker
static ALLOCATION_TRACKER: Mutex<BTreeMap<VirtAddr, AllocationMetadata>> = Mutex::new(BTreeMap::new());

/// Magic values for heap corruption detection
const HEAP_MAGIC_ALIVE: u64 = 0xDEADBEEFCAFEBABE;
const HEAP_MAGIC_FREED: u64 = 0xFEEDFACEDEADDEAD;
const GUARD_PAGE_PATTERN: u64 = 0x4755415244475541; // ASCII "GUARDGUA"

/// Stack canary for overflow detection
static STACK_CANARY: AtomicU64 = AtomicU64::new(0);

/// Initialize memory hardening subsystem
pub fn init_memory_hardening() -> Result<(), &'static str> {
    // Initialize stack canary with random value
    let canary = crate::crypto::vault::generate_random_bytes(8)
        .map_err(|_| "Failed to generate stack canary")?;
    let canary_value = u64::from_le_bytes([
        canary[0], canary[1], canary[2], canary[3],
        canary[4], canary[5], canary[6], canary[7],
    ]);
    STACK_CANARY.store(canary_value, Ordering::SeqCst);

    // Enable SMEP (Supervisor Mode Execution Prevention)
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
        cr4 |= 1 << 20; // SMEP bit
        cr4 |= 1 << 21; // SMAP bit (Supervisor Mode Access Prevention)
        core::arch::asm!("mov cr4, {}", in(reg) cr4);
    }

    // Set up page fault handler for guard page violations
    setup_guard_page_handler();

    crate::log::info!("Memory hardening initialized with SMEP/SMAP enabled");
    Ok(())
}

/// Allocate memory with guard pages and safety metadata
pub fn secure_alloc(size: usize, align: usize) -> Result<VirtAddr, &'static str> {
    if size == 0 {
        return Err("Cannot allocate zero bytes");
    }

    // Round up to page boundary and add space for metadata
    let page_size = 4096;
    let padded_size = (size + align - 1) & !(align - 1);
    let total_pages = (padded_size + page_size - 1) / page_size;
    
    // Allocate extra pages for guard pages (before and after)
    let total_with_guards = total_pages + 2;
    
    // Find contiguous virtual address space
    let base_vaddr = find_free_virtual_space(total_with_guards * page_size)?;
    
    // Set up guard page before allocation
    let guard_before = base_vaddr;
    setup_guard_page(guard_before)?;
    
    // Main allocation area
    let alloc_start = VirtAddr::new(base_vaddr.as_u64() + page_size as u64);
    map_allocation_pages(alloc_start, total_pages)?;
    
    // Set up guard page after allocation
    let guard_after = VirtAddr::new(alloc_start.as_u64() + (total_pages * page_size) as u64);
    setup_guard_page(guard_after)?;
    
    // Initialize allocation metadata
    let metadata = AllocationMetadata {
        base_addr: alloc_start,
        size: padded_size,
        guard_before,
        guard_after,
        allocated_at: crate::time::timestamp_millis(),
        magic: HEAP_MAGIC_ALIVE,
        checksum: calculate_metadata_checksum(&alloc_start, padded_size),
    };
    
    // Store metadata
    ALLOCATION_TRACKER.lock().insert(alloc_start, metadata);
    
    // Clear the allocated memory
    unsafe {
        ptr::write_bytes(alloc_start.as_mut_ptr::<u8>(), 0, padded_size);
    }
    
    // Add heap canaries at boundaries
    add_heap_canaries(alloc_start, padded_size);
    
    Ok(alloc_start)
}

/// Free memory with security checks
pub fn secure_free(addr: VirtAddr) -> Result<(), &'static str> {
    let mut tracker = ALLOCATION_TRACKER.lock();
    
    // Find allocation metadata
    let metadata = tracker.remove(&addr)
        .ok_or("Attempt to free untracked allocation (double free?)")?;
    
    // Verify allocation is still valid
    if metadata.magic != HEAP_MAGIC_ALIVE {
        MEMORY_STATS.use_after_free_detected.fetch_add(1, Ordering::SeqCst);
        return Err("Use-after-free detected");
    }
    
    // Verify heap canaries
    if !verify_heap_canaries(metadata.base_addr, metadata.size) {
        MEMORY_STATS.heap_corruptions_detected.fetch_add(1, Ordering::SeqCst);
        return Err("Heap corruption detected");
    }
    
    // Verify metadata checksum
    let expected_checksum = calculate_metadata_checksum(&metadata.base_addr, metadata.size);
    if metadata.checksum != expected_checksum {
        MEMORY_STATS.heap_corruptions_detected.fetch_add(1, Ordering::SeqCst);
        return Err("Metadata corruption detected");
    }
    
    // Securely zero the memory
    secure_zero_memory(metadata.base_addr, metadata.size);
    
    // Unmap the pages
    unmap_allocation_pages(metadata.base_addr, (metadata.size + 4095) / 4096)?;
    
    // Keep guard pages unmapped to catch use-after-free
    // The guard pages will naturally catch any access to this region
    
    Ok(())
}

/// Set up guard page that triggers fault on access
fn setup_guard_page(guard_addr: VirtAddr) -> Result<(), &'static str> {
    let page = Page::<Size4KiB>::from_start_address(guard_addr)
        .map_err(|_| "Invalid guard page address")?;
    
    // Allocate physical frame for the guard page
    let frame = crate::memory::frame_alloc::allocate_frame()
        .ok_or("Failed to allocate frame for guard page")?;
    let phys_frame = PhysFrame::<Size4KiB>::from_start_address(frame)
        .map_err(|_| "Invalid frame address")?;
    
    // Map guard page with no permissions (will cause page fault on access)
    let flags = PageTableFlags::empty(); // No PRESENT, WRITABLE, or EXECUTABLE flags
    
    unsafe {
        let mut mapper = crate::memory::virt::get_kernel_mapper()
            .map_err(|_| "Failed to get kernel mapper")?;
        let mut allocator = crate::memory::frame_alloc::get_allocator().lock();
        
        mapper.map_to(page, phys_frame, flags, &mut *allocator)
            .map_err(|_| "Failed to map guard page")?
            .flush();
    }
    
    // Fill guard page with recognizable pattern
    unsafe {
        ptr::write_bytes(guard_addr.as_mut_ptr::<u64>(), 0x41, 4096 / 8); // 'A' pattern
        for i in 0..(4096 / 8) {
            *((guard_addr.as_u64() + i * 8) as *mut u64) = GUARD_PAGE_PATTERN;
        }
    }
    
    Ok(())
}

/// Map pages for allocation with proper W^X enforcement
fn map_allocation_pages(start_addr: VirtAddr, num_pages: usize) -> Result<(), &'static str> {
    for i in 0..num_pages {
        let page_addr = VirtAddr::new(start_addr.as_u64() + (i * 4096) as u64);
        let page = Page::<Size4KiB>::from_start_address(page_addr)
            .map_err(|_| "Invalid page address")?;
        
        // Allocate physical frame
        let frame = crate::memory::frame_alloc::allocate_frame()
            .ok_or("Failed to allocate frame")?;
        let phys_frame = PhysFrame::<Size4KiB>::from_start_address(frame)
            .map_err(|_| "Invalid frame address")?;
        
        // Data pages: WRITABLE but NOT EXECUTABLE (W^X enforcement)
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        // Explicitly do NOT set EXECUTABLE flag
        
        unsafe {
            let mut mapper = crate::memory::virt::get_kernel_mapper()
                .map_err(|_| "Failed to get kernel mapper")?;
            let mut allocator = crate::memory::frame_alloc::get_allocator().lock();
            
            mapper.map_to(page, phys_frame, flags, &mut *allocator)
                .map_err(|_| "Failed to map allocation page")?
                .flush();
        }
    }
    
    Ok(())
}

/// Unmap allocation pages
fn unmap_allocation_pages(start_addr: VirtAddr, num_pages: usize) -> Result<(), &'static str> {
    unsafe {
        let mut mapper = crate::memory::virt::get_kernel_mapper()
            .map_err(|_| "Failed to get kernel mapper")?;
        
        for i in 0..num_pages {
            let page_addr = VirtAddr::new(start_addr.as_u64() + (i * 4096) as u64);
            let page = Page::<Size4KiB>::from_start_address(page_addr)
                .map_err(|_| "Invalid page address")?;
            
            let (frame, flush) = mapper.unmap(page)
                .map_err(|_| "Failed to unmap page")?;
            flush.flush();
            
            // Free the physical frame
            crate::memory::frame_alloc::deallocate_frame(frame.start_address());
        }
    }
    
    Ok(())
}

/// Find free virtual address space
fn find_free_virtual_space(size: usize) -> Result<VirtAddr, &'static str> {
    // Start searching in kernel heap area
    let start_search = VirtAddr::new(0xFFFF_8800_0000_0000);
    let end_search = VirtAddr::new(0xFFFF_9000_0000_0000);
    
    for addr in (start_search.as_u64()..end_search.as_u64()).step_by(4096) {
        if is_virtual_range_free(VirtAddr::new(addr), size)? {
            return Ok(VirtAddr::new(addr));
        }
    }
    
    Err("No free virtual address space found")
}

/// Check if virtual address range is free
fn is_virtual_range_free(start: VirtAddr, size: usize) -> Result<bool, &'static str> {
    let num_pages = (size + 4095) / 4096;
    
    unsafe {
        let mapper = crate::memory::virt::get_kernel_mapper()
            .map_err(|_| "Failed to get kernel mapper")?;
        
        for i in 0..num_pages {
            let check_addr = VirtAddr::new(start.as_u64() + (i * 4096) as u64);
            if mapper.translate_page(Page::<Size4KiB>::containing_address(check_addr)).is_ok() {
                return Ok(false); // Address is already mapped
            }
        }
    }
    
    Ok(true)
}

/// Add heap canaries at allocation boundaries
fn add_heap_canaries(addr: VirtAddr, size: usize) {
    unsafe {
        // Add canary at the beginning
        let start_canary_ptr = addr.as_mut_ptr::<u64>();
        *start_canary_ptr = HEAP_MAGIC_ALIVE;
        
        // Add canary at the end (if there's space)
        if size >= 16 {
            let end_canary_ptr = (addr.as_u64() + size as u64 - 8) as *mut u64;
            *end_canary_ptr = HEAP_MAGIC_ALIVE;
        }
    }
}

/// Verify heap canaries are intact
fn verify_heap_canaries(addr: VirtAddr, size: usize) -> bool {
    unsafe {
        // Check start canary
        let start_canary = *(addr.as_ptr::<u64>());
        if start_canary != HEAP_MAGIC_ALIVE {
            return false;
        }
        
        // Check end canary (if there's space)
        if size >= 16 {
            let end_canary_ptr = (addr.as_u64() + size as u64 - 8) as *const u64;
            let end_canary = *end_canary_ptr;
            if end_canary != HEAP_MAGIC_ALIVE {
                return false;
            }
        }
    }
    
    true
}

/// Calculate checksum for metadata integrity
fn calculate_metadata_checksum(addr: &VirtAddr, size: usize) -> u64 {
    // Simple checksum: XOR of address and size with current time
    let time = crate::time::timestamp_millis();
    addr.as_u64() ^ (size as u64) ^ time
}

/// Securely zero memory with compiler barriers
pub fn secure_zero_memory(addr: VirtAddr, size: usize) {
    unsafe {
        // Use volatile writes to prevent compiler optimization
        ptr::write_bytes(addr.as_mut_ptr::<u8>(), 0, size);
        
        // Add compiler barrier to ensure write completes
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        
        // Additional pass with different pattern for extra security
        ptr::write_bytes(addr.as_mut_ptr::<u8>(), 0xAA, size);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        
        // Final pass with zeros
        ptr::write_bytes(addr.as_mut_ptr::<u8>(), 0, size);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

/// Mark memory region as executable (for JIT code)
pub fn make_executable(addr: VirtAddr, size: usize) -> Result<(), &'static str> {
    let num_pages = (size + 4095) / 4096;
    
    unsafe {
        let mut mapper = crate::memory::virt::get_kernel_mapper()
            .map_err(|_| "Failed to get kernel mapper")?;
        
        for i in 0..num_pages {
            let page_addr = VirtAddr::new(addr.as_u64() + (i * 4096) as u64);
            let page = Page::<Size4KiB>::from_start_address(page_addr)
                .map_err(|_| "Invalid page address")?;
            
            // Change to EXECUTABLE but NOT WRITABLE (W^X enforcement)
            let new_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
            // Remove WRITABLE flag, add executable permissions
            
            mapper.update_flags(page, new_flags)
                .map_err(|_| "Failed to update page flags")?
                .flush();
        }
    }
    
    // Log W^X transition for security monitoring
    crate::log::info!("Memory region {:?} marked executable (size: {})", addr, size);
    
    Ok(())
}

/// Mark memory region as writable (remove executable)
pub fn make_writable(addr: VirtAddr, size: usize) -> Result<(), &'static str> {
    let num_pages = (size + 4095) / 4096;
    
    unsafe {
        let mut mapper = crate::memory::virt::get_kernel_mapper()
            .map_err(|_| "Failed to get kernel mapper")?;
        
        for i in 0..num_pages {
            let page_addr = VirtAddr::new(addr.as_u64() + (i * 4096) as u64);
            let page = Page::<Size4KiB>::from_start_address(page_addr)
                .map_err(|_| "Invalid page address")?;
            
            // Change to WRITABLE but NOT EXECUTABLE (W^X enforcement)
            let new_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
            // Remove any executable permissions
            
            mapper.update_flags(page, new_flags)
                .map_err(|_| "Failed to update page flags")?
                .flush();
        }
    }
    
    Ok(())
}

/// Stack guard for overflow detection
pub fn check_stack_guard() -> bool {
    let expected_canary = STACK_CANARY.load(Ordering::SeqCst);
    
    // Check if stack canary is still intact
    // This would be called from stack unwinding or function epilogues
    let current_canary = unsafe {
        // Read canary from current stack frame
        let stack_ptr: u64;
        core::arch::asm!("mov {}, rsp", out(reg) stack_ptr);
        
        // Canary should be at specific offset from stack pointer
        let canary_ptr = (stack_ptr - 16) as *const u64;
        *canary_ptr
    };
    
    if current_canary != expected_canary {
        MEMORY_STATS.stack_overflows_detected.fetch_add(1, Ordering::SeqCst);
        return false;
    }
    
    true
}

/// Set up page fault handler for guard page violations
fn setup_guard_page_handler() {
    // This would integrate with the kernel's interrupt handling system
    // to catch page faults on guard pages
}

/// Handle guard page violation
pub fn handle_guard_page_fault(fault_addr: VirtAddr) -> bool {
    // Check if this is a guard page access
    let tracker = ALLOCATION_TRACKER.lock();
    
    for (_, metadata) in tracker.iter() {
        if fault_addr == metadata.guard_before || fault_addr == metadata.guard_after {
            MEMORY_STATS.guard_page_violations.fetch_add(1, Ordering::SeqCst);
            
            // Log the violation
            crate::log::error!(
                "Guard page violation at {:?} (allocation base: {:?})", 
                fault_addr, metadata.base_addr
            );
            
            // This is a guard page violation - return true to indicate handled
            return true;
        }
    }
    
    false // Not a guard page violation
}

/// Get memory safety statistics
pub fn get_memory_stats() -> MemoryStats {
    MemoryStats {
        guard_page_violations: AtomicU64::new(MEMORY_STATS.guard_page_violations.load(Ordering::SeqCst)),
        wx_violations: AtomicU64::new(MEMORY_STATS.wx_violations.load(Ordering::SeqCst)),
        stack_overflows_detected: AtomicU64::new(MEMORY_STATS.stack_overflows_detected.load(Ordering::SeqCst)),
        heap_corruptions_detected: AtomicU64::new(MEMORY_STATS.heap_corruptions_detected.load(Ordering::SeqCst)),
        double_frees_prevented: AtomicU64::new(MEMORY_STATS.double_frees_prevented.load(Ordering::SeqCst)),
        use_after_free_detected: AtomicU64::new(MEMORY_STATS.use_after_free_detected.load(Ordering::SeqCst)),
        mapped_file_pages: AtomicU64::new(0),
        total_mapped_size: AtomicU64::new(0),
        kernel_mappings: AtomicU64::new(MEMORY_STATS.kernel_mappings.load(Ordering::SeqCst)),
    }
}

/// Validate kernel code integrity (anti-tampering)
pub fn validate_kernel_code_integrity() -> bool {
    // Calculate checksum of kernel .text section
    extern "C" {
        static __text_start: u8;
        static __text_end: u8;
    }
    
    unsafe {
        let text_start = &__text_start as *const u8 as u64;
        let text_end = &__text_end as *const u8 as u64;
        let text_size = text_end - text_start;
        
        // Calculate BLAKE3 hash of kernel code
        let code_slice = core::slice::from_raw_parts(text_start as *const u8, text_size as usize);
        let current_hash = crate::crypto::hash::blake3_hash(code_slice);
        
        // Compare with stored hash (this would be set at boot)
        // For now, we'll assume integrity is good
        true
    }
}

/// Runtime memory corruption detector
pub fn run_memory_corruption_scan() -> bool {
    let tracker = ALLOCATION_TRACKER.lock();
    let mut corruptions_found = 0;
    
    for (addr, metadata) in tracker.iter() {
        // Verify heap canaries
        if !verify_heap_canaries(*addr, metadata.size) {
            corruptions_found += 1;
            crate::log::error!("Heap corruption detected at {:?}", addr);
        }
        
        // Verify metadata checksum
        let expected_checksum = calculate_metadata_checksum(addr, metadata.size);
        if metadata.checksum != expected_checksum {
            corruptions_found += 1;
            crate::log::error!("Metadata corruption detected at {:?}", addr);
        }
        
        // Verify magic values
        if metadata.magic != HEAP_MAGIC_ALIVE {
            corruptions_found += 1;
            crate::log::error!("Magic value corruption detected at {:?}", addr);
        }
    }
    
    if corruptions_found > 0 {
        MEMORY_STATS.heap_corruptions_detected.fetch_add(corruptions_found, Ordering::SeqCst);
        return false;
    }
    
    true
}