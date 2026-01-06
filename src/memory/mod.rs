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
// ============================================================================
// SUBMODULES
// ============================================================================
pub mod boot_memory;
pub mod buddy_alloc;
pub mod dma;
pub mod frame_alloc;
pub mod hardening;
pub mod heap;
pub mod kaslr;
pub mod layout;
pub mod mmio;
pub mod mmu;
pub mod page_allocator;
pub mod page_info;
pub mod paging;
pub mod phys;
pub mod proof;
pub mod region;
pub mod safety;
pub mod secure_memory;
pub mod virt;
pub mod virtual_memory;
// ============================================================================
// RE-EXPORTS
// ============================================================================
pub use x86_64::{PhysAddr, VirtAddr};
pub use buddy_alloc as allocator;
pub use secure_memory as memory;
pub use hardening::{
    get_all_process_regions, init_module_memory_protection, read_bytes, verify_kernel_data_integrity,
    verify_kernel_page_tables,
};

// ============================================================================
// ADDRESS CONVERSION
// ============================================================================
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_u64() + layout::DIRECTMAP_BASE)
}

pub fn virt_to_phys(virt: VirtAddr) -> Option<PhysAddr> {
    if virt.as_u64() >= layout::DIRECTMAP_BASE
        && virt.as_u64() < layout::DIRECTMAP_BASE + layout::DIRECTMAP_SIZE
    {
        Some(PhysAddr::new(virt.as_u64() - layout::DIRECTMAP_BASE))
    } else {
        None
    }
}
// ============================================================================
// UNIFIED VIRTUAL MEMORY INTERFACE
// ============================================================================
use core::sync::atomic::{AtomicBool, Ordering};
static VM_UNIFIED_INITIALIZED: AtomicBool = AtomicBool::new(false);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProtection {
    None,
    Read,
    ReadWrite,
    ReadExecute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Anonymous,
    KernelCode,
    KernelData,
    UserCode,
    UserData,
    UserHeap,
    UserStack,
    Device,
    SecureCapsule,
    Shared,
}

pub fn init_unified_vm() -> Result<(), &'static str> {
    if VM_UNIFIED_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let cr3 = paging::get_current_cr3();
    virt::init(cr3).map_err(|_| "Failed to init virt")?;
    virtual_memory::init().map_err(|_| "Failed to init virtual_memory")?;
    memory::init().map_err(|_| "Failed to init memory")?;
    crate::log_info!("Unified VM subsystem initialized");
    Ok(())
}

pub fn map_memory(
    va: VirtAddr,
    size: usize,
    protection: MemoryProtection,
    mem_type: MemoryType,
) -> Result<(), &'static str> {
    let vm_protection = match protection {
        MemoryProtection::None => virtual_memory::VmProtection::None,
        MemoryProtection::Read => virtual_memory::VmProtection::Read,
        MemoryProtection::ReadWrite => virtual_memory::VmProtection::ReadWrite,
        MemoryProtection::ReadExecute => virtual_memory::VmProtection::ReadExecute,
    };

    let vm_type = match mem_type {
        MemoryType::Anonymous => virtual_memory::VmType::Anonymous,
        MemoryType::KernelCode | MemoryType::UserCode => virtual_memory::VmType::Code,
        MemoryType::KernelData | MemoryType::UserData => virtual_memory::VmType::Data,
        MemoryType::UserHeap => virtual_memory::VmType::Heap,
        MemoryType::UserStack => virtual_memory::VmType::Stack,
        MemoryType::Device => virtual_memory::VmType::Device,
        MemoryType::SecureCapsule => virtual_memory::VmType::File,
        MemoryType::Shared => virtual_memory::VmType::Shared,
    };

    virtual_memory::map_memory_range(va, size, vm_protection, vm_type)?;
    Ok(())
}

pub fn unmap_memory(va: VirtAddr, size: usize) -> Result<(), &'static str> {
    if virtual_memory::find_vm_area_by_address(va).is_some() {
        let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        for i in 0..page_count {
            let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
            let _ = virt::unmap_page(page_va);
        }
    }
    Ok(())
}

pub fn translate_virtual(va: VirtAddr) -> Option<PhysAddr> {
    virt::translate_addr(va).ok()
}

pub fn is_address_mapped(va: VirtAddr) -> bool {
    virt::is_mapped(va) || paging::is_mapped(va)
}

pub fn handle_unified_page_fault(fault_addr: VirtAddr, error_code: u64) -> Result<(), &'static str> {
    if virtual_memory::handle_page_fault(fault_addr, error_code).is_ok() {
        return Ok(());
    }

    virt::handle_page_fault(fault_addr, error_code).map_err(|_| "Page fault handling failed")
}

pub fn allocate_secure_region(
    size: usize,
    owner_process: u64,
    security_level: memory::SecurityLevel,
) -> Result<VirtAddr, &'static str> {
    memory::allocate_memory(size, memory::RegionType::Capsule, security_level, owner_process)
        .map_err(|_| "Failed to allocate secure region")
}

pub fn validate_access(process_id: u64, va: VirtAddr, write: bool) -> bool {
    memory::validate_memory_access(process_id, va, write)
}

#[derive(Debug)]
pub struct UnifiedVmStats {
    pub virt_stats: virt::VmStatsSnapshot,
    pub vmem_stats: virtual_memory::VmStats,
    pub memory_stats: memory::ManagerStats,
}

pub fn get_unified_vm_stats() -> UnifiedVmStats {
    UnifiedVmStats {
        virt_stats: virt::get_stats(),
        vmem_stats: virtual_memory::get_vm_stats(),
        memory_stats: memory::get_memory_stats(),
    }
}

pub fn flush_tlb_range(start: VirtAddr, size: usize) {
    virtual_memory::flush_tlb_range(start, size);
}

pub fn flush_tlb_all() {
    virtual_memory::flush_all_tlb();
}
// ============================================================================
// INITIALIZATION
// ============================================================================
pub fn init_all_memory_subsystems() -> Result<(), &'static str> {
    layout::validate_layout().map_err(|_| "Layout validation failed")?;
    phys::init(PhysAddr::new(0x100000), PhysAddr::new(0x40000000)).map_err(|_| "Physical memory init failed")?;
    frame_alloc::init().map_err(|_| "Frame allocator init failed")?;
    heap::init().map_err(|_| "Heap init failed")?;
    allocator::init().map_err(|_| "Allocator init failed")?;
    safety::init().map_err(|_| "Safety module init failed")?;
    hardening::init_module_memory_protection();
    kaslr::validate().map_err(|_| "KASLR validation failed")?;

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

// ============================================================================
// STATISTICS
// ============================================================================
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
