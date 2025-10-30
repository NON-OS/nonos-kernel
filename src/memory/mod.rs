#![no_std]

extern crate alloc;

pub mod nonos_layout;
pub mod nonos_phys;
pub mod nonos_frame_alloc;
pub mod nonos_mmu;
pub mod nonos_heap;
pub mod nonos_kaslr;
pub mod nonos_safety;
pub mod nonos_hardening;
pub mod nonos_proof;
pub mod nonos_boot_memory;
pub mod nonos_alloc;
pub mod nonos_mmio;
pub mod nonos_dma;
pub mod nonos_virt;
pub mod nonos_paging;
pub mod nonos_page_allocator;
pub mod nonos_page_info;
pub mod nonos_region;
pub mod nonos_virtual_memory;
pub mod nonos_memory;

pub use x86_64::{PhysAddr, VirtAddr};

pub use nonos_layout as layout;
pub use nonos_phys as phys;
pub use nonos_frame_alloc as frame_alloc;
pub use nonos_mmu as mmu;
pub use nonos_heap as heap;
pub use nonos_kaslr as kaslr;
pub use nonos_safety as safety;
pub use nonos_hardening as hardening;
pub use nonos_proof as proof;
pub use nonos_boot_memory as boot_memory;
pub use nonos_alloc as allocator;
pub use nonos_mmio as mmio;
pub use nonos_dma as dma;
pub use nonos_virt as virt;
pub use nonos_paging as paging;
pub use nonos_page_allocator as page_allocator;
pub use nonos_page_info as page_info;
pub use nonos_region as region;
pub use nonos_virtual_memory as virtual_memory;
pub use nonos_memory as memory;

use crate::memory::paging::PagePermissions;

pub use hardening::{init_module_memory_protection, verify_kernel_data_integrity, verify_kernel_page_tables, get_all_process_regions, read_bytes};

pub fn init_all_memory_subsystems() -> Result<(), &'static str> {
    layout::validate_layout()?;
    
    phys::init(PhysAddr::new(0x100000), PhysAddr::new(0x40000000))?;
    frame_alloc::init()?;
    heap::init()?;
    allocator::init()?;
    safety::init()?;
    hardening::init_module_memory_protection();
    kaslr::validate()?;
    
    Ok(())
}

pub fn verify_all_memory_integrity() -> Result<(), &'static str> {
    if !heap::verify_heap_integrity() {
        return Err("Heap integrity check failed");
    }
    
    if !safety::verify_stack_integrity() {
        return Err("Stack integrity check failed");
    }
    
    if !kaslr::verify_slide_integrity() {
        return Err("KASLR integrity check failed");
    }
    
    if !verify_kernel_data_integrity() {
        return Err("Kernel data integrity check failed");
    }
    
    if !verify_kernel_page_tables() {
        return Err("Page table integrity check failed");
    }
    
    Ok(())
}

pub struct MemorySystemStats {
    pub heap_stats: heap::HeapStats,
    pub alloc_stats: allocator::AllocStats,
    pub safety_stats: safety::MemoryStats,
    pub total_physical_memory: u64,
    pub total_virtual_memory: u64,
    pub active_allocations: usize,
}

pub fn get_memory_system_stats() -> MemorySystemStats {
    MemorySystemStats {
        heap_stats: heap::get_heap_stats(),
        alloc_stats: allocator::get_allocation_stats(),
        safety_stats: safety::get_stats(),
        total_physical_memory: phys::total_memory(),
        total_virtual_memory: layout::VMAP_SIZE,
        active_allocations: allocator::get_allocation_stats().active_ranges,
    }
}