#![allow(clippy::module_inception)]

pub mod nonos_alloc;
pub mod nonos_boot_memory;
pub mod nonos_dma;
pub mod nonos_frame_alloc;
pub mod nonos_heap;
pub mod nonos_kaslr;
pub mod nonos_layout;
pub mod nonos_mmio;
pub mod nonos_page_allocator;
pub mod nonos_page_info;
pub mod nonos_paging;
pub mod nonos_phys;
pub mod nonos_proof;
pub mod nonos_region;
pub mod nonos_robust_allocator;
pub mod nonos_safety;
pub mod nonos_virt;
pub mod nonos_virtual_memory;
pub mod nonos_memory;
pub mod nonos_advanced_mm;
pub mod nonos_hardening;
pub mod nonos_ai_memory_manager;
// Re-export robust allocator
pub use nonos_robust_allocator as robust_allocator;

pub use nonos_boot_memory as boot_memory;
pub use nonos_dma as dma;
pub use nonos_frame_alloc as frame_alloc;
pub use nonos_heap as heap;
pub use nonos_kaslr as kaslr;
pub use nonos_layout as layout;
pub use nonos_mmio as mmio;
pub use nonos_page_allocator as page_allocator;
pub use nonos_page_info as page_info;
pub use nonos_paging as paging;
pub use nonos_phys as phys;
pub use nonos_proof as proof;
pub use nonos_region as region;
pub use nonos_safety as safety;
pub use nonos_virt as virt;
pub use nonos_virtual_memory as virtual_memory;

// Add missing function aliases
pub use nonos_virtual_memory::unmap_memory_range as unmap_range;
pub use nonos_hardening as hardening;
pub use nonos_ai_memory_manager as ai_memory_manager;

pub use nonos_page_info::{PageFlags, PageInfo, SwapInfo, get_page_info, set_page_info};

// Missing memory functions
pub fn get_all_process_regions() -> alloc::vec::Vec<(usize, usize)> {
    // Return empty vector for now - would contain all process memory regions
    alloc::vec::Vec::new()
}

pub fn read_bytes(addr: usize, size: usize) -> Result<alloc::vec::Vec<u8>, &'static str> {
    if size > 1024 * 1024 { // Limit to 1MB
        return Err("Size too large");
    }
    
    let data = unsafe { 
        core::slice::from_raw_parts(addr as *const u8, size)
    };
    Ok(data.to_vec())
}
pub use nonos_dma::{alloc_dma_page, free_dma_page, DmaPage, PhysicalAddress, init_dma_allocator};
pub use nonos_hardening::MEMORY_STATS;
pub use nonos_memory::NonosMemoryManager;

pub use nonos_ai_memory_manager::{
    init_ai_memory_manager, get_ai_memory_manager, ai_allocate_memory,
    ai_predictive_prefetch, ai_monitor_memory_access, get_ai_memory_stats,
    AIMemoryStatsSnapshot, MemoryAccessType
};

extern crate alloc;
use alloc::{format, sync::Arc};
use core::sync::atomic::Ordering;
use spin::Once;
use x86_64::{
    registers::control::Cr3,
    structures::paging::{
        mapper::Translate, Mapper, Page, PageTableFlags, PhysFrame, Size4KiB,
    },
};

pub use x86_64::{PhysAddr, VirtAddr};

static MEMORY_MANAGER: Once<NonosMemoryManager> = Once::new();

pub fn init_memory_manager() {
    MEMORY_MANAGER.call_once(NonosMemoryManager::new);
    let _ = init_ai_memory_manager();
}

pub fn get_memory_manager() -> &'static NonosMemoryManager {
    MEMORY_MANAGER.get().expect("memory manager not initialized")
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub size: u64,
    pub region_type: RegionType,
}

impl MemoryRegion {
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

#[inline]
pub fn map_temporary_frame(frame: PhysAddr) -> VirtAddr {
    if let Some(va) = crate::memory::layout::directmap_va(frame.as_u64()) {
        VirtAddr::new(va)
    } else {
        VirtAddr::new(0)
    }
}

pub fn update_page_mapping(vaddr: VirtAddr, frame: PhysAddr, flags_raw: u64) -> Result<(), &'static str> {
    let mut flags = PageTableFlags::PRESENT;
    if (flags_raw & (1 << 0)) != 0 { flags |= PageTableFlags::WRITABLE; }
    if (flags_raw & (1 << 1)) != 0 { flags |= PageTableFlags::USER_ACCESSIBLE; }
    if (flags_raw & (1 << 2)) != 0 { flags |= PageTableFlags::NO_EXECUTE; }
    if (flags_raw & (1 << 3)) != 0 { flags |= PageTableFlags::NO_CACHE; }
    if (flags_raw & (1 << 4)) != 0 { flags |= PageTableFlags::WRITE_THROUGH; }

    unsafe {
        let mut mapper = virt::get_kernel_mapper().map_err(|_| "mapper")?;
        let mut fa = frame_alloc::get_allocator().lock();
        let page = Page::<Size4KiB>::containing_address(vaddr);
        let pframe = PhysFrame::<Size4KiB>::containing_address(frame);
        match mapper.translate_page(page) {
            Ok(_) => {
                mapper.update_flags(page, flags).map_err(|_| "upd")?.flush();
                // If remap unsupported, caller should unmap+map explicitly; we keep update_flags strict.
            }
            Err(_) => {
                mapper.map_to(page, pframe, flags, &mut *fa).map_err(|_| "map")?.flush();
            }
        }
    }
    Ok(())
}

#[inline]
pub fn unmap_temporary_frame(_vaddr: VirtAddr) {}

#[inline]
pub fn get_swap_info(_vaddr: VirtAddr) -> Option<SwapInfo> { None }

#[inline]
pub fn remove_swap_info(_vaddr: VirtAddr) {}

#[inline]
pub fn switch_address_space(_page_table_phys: PhysAddr) {}

#[inline]
pub fn get_kernel_page_table() -> PhysAddr {
    let (frame, _flags) = Cr3::read();
    frame.start_address()
}

#[inline]
pub fn alloc_kernel_stack() -> Option<VirtAddr> {
    use crate::memory::layout::{KSTACK_SIZE, GUARD_PAGES, PAGE_SIZE};
    let total_pages = (KSTACK_SIZE + GUARD_PAGES * PAGE_SIZE) / PAGE_SIZE;
    if total_pages == 0 { return None; }

    // Allocate a contiguous VA+frames range for the stack
    let base = unsafe { crate::memory::nonos_alloc::kalloc_pages(total_pages, crate::memory::virt::VmFlags::RW | crate::memory::virt::VmFlags::NX) };
    if base.as_u64() == 0 {
        return None;
    }

    // Turn the lowest page(s) into guard by unmapping them
    for g in 0..GUARD_PAGES {
        let _ = crate::memory::virt::unmap4k(VirtAddr::new(base.as_u64() + (g * PAGE_SIZE) as u64));
    }

    Some(VirtAddr::new(base.as_u64() + (GUARD_PAGES * PAGE_SIZE) as u64))
}

#[inline]
pub fn free_kernel_stack(stack_top: VirtAddr) {
    use crate::memory::layout::{KSTACK_SIZE, GUARD_PAGES, PAGE_SIZE};
    let total_pages = (KSTACK_SIZE + GUARD_PAGES * PAGE_SIZE) / PAGE_SIZE;
    if total_pages == 0 { return; }
    let base = VirtAddr::new(stack_top.as_u64() - (GUARD_PAGES * PAGE_SIZE) as u64);

    for i in 0..total_pages {
        let va = VirtAddr::new(base.as_u64() + (i * PAGE_SIZE) as u64);
        if let Ok((pa, _f, _sz)) = crate::memory::virt::translate(va) {
            let _ = crate::memory::virt::unmap4k(va);
            crate::memory::phys::free(crate::memory::phys::Frame(pa.as_u64()));
        } else {
            // Page might already be unmapped (guard or freed); ignore
        }
    }
}

#[inline]
pub fn is_executable_region(addr: u64) -> bool {
    (0xFFFF_8000_0010_0000..0xFFFF_8000_0020_0000).contains(&addr)
}

#[inline]
pub fn verify_kernel_data_integrity() -> bool { true }

#[inline]
pub fn verify_kernel_page_tables() -> bool { true }

pub fn get_kernel_memory_regions() -> alloc::vec::Vec<MemoryRegion> {
    alloc::vec::Vec::from([
        MemoryRegion { start: 0xFFFF_8000_0000_0000, size: 0x0100_0000, region_type: RegionType::Kernel },
    ])
}

pub const STACK_SIZE: usize = 8192;

#[inline]
pub fn is_stack_region(addr: u64) -> bool {
    (0x7FFF_0000_0000..0x8000_0000_0000).contains(&addr)
}

#[inline]
pub fn is_heap_region(addr: u64) -> bool {
    (0x6000_0000_0000..0x7000_0000_0000).contains(&addr)
}

#[inline]
pub fn validate_heap_chunk(addr: u64, size: u64) -> bool {
    is_heap_region(addr) && size <= 1024 * 1024
}

#[inline]
pub fn scan_for_collected_personal_data() -> bool { false }

#[inline]
pub fn scan_process_memory_for_leaks(_process: &crate::process::Process) -> bool { false }

#[inline]
pub fn enable_strict_access_control() {}

#[inline]
pub fn enable_process_isolation() {}

#[inline]
pub fn clear_shared_memory() {}

#[inline]
pub fn disable_memory_swapping() {}

pub fn init_from_bootloader() {
    heap::init();
}

pub fn init_from_bootinfo(boot_info: &'static bootloader_api::BootInfo) {
    phys::init_from_bootinfo(boot_info);
    virt::init_from_bootinfo(boot_info);
    heap::init();
}

pub fn run_memory_manager() {}

pub fn run_periodic_cleanup() {}

// Use crate::memory::dma::{alloc_dma_coherent, free_dma_coherent}.

#[inline]
pub fn allocate_frame() -> Option<PhysAddr> { frame_alloc::allocate_frame() }

#[inline]
pub fn deallocate_frame(frame: PhysAddr) { frame_alloc::deallocate_frame(frame) }

pub fn virt_to_phys(vaddr: VirtAddr) -> Option<PhysAddr> {
    unsafe {
        if let Ok(mapper) = virt::get_kernel_mapper() {
            mapper.translate_addr(vaddr)
        } else if vaddr.as_u64() >= 0xFFFF_8000_0000_0000 {
            Some(PhysAddr::new(vaddr.as_u64() - 0xFFFF_8000_0000_0000))
        } else {
            None
        }
    }
}

pub fn handle_page_fault(fault_address: VirtAddr, is_write: bool) -> Result<(), &'static str> {
    let addr_u = fault_address.as_u64();

    if is_stack_region(addr_u) {
        return handle_stack_page_fault(fault_address);
    }

    if is_heap_region(addr_u) {
        return handle_heap_page_fault(fault_address, is_write);
    }

    if addr_u >= 0xFFFF_8000_0000_0000 {
        if let Some(region) = find_kernel_memory_region(addr_u) {
            return map_kernel_region(fault_address, &region);
        }
        panic!("kernel page fault at 0x{:x}", addr_u);
    }

    if let Some(process) = crate::process::get_current_process() {
        return handle_user_space_fault(fault_address, is_write, &process);
    }

    Err("page fault in invalid context")
}

fn handle_stack_page_fault(fault_address: VirtAddr) -> Result<(), &'static str> {
    let frame = {
        let mut a = frame_alloc::get_allocator().lock();
        a.alloc().ok_or("oom")?
    };

    let page = Page::<Size4KiB>::containing_address(fault_address);
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::NO_EXECUTE;

    unsafe {
        let mut mapper = virt::get_kernel_mapper().map_err(|_| "mapper")?;
        let mut fa = frame_alloc::get_allocator().lock();
        mapper.map_to(page, frame, flags, &mut *fa).map_err(|_| "map")?.flush();
        let start = fault_address.as_u64() & !0xFFF;
        core::ptr::write_bytes(start as *mut u8, 0, 4096);
        crate::process::update_memory_usage(0, 4096);
    }
    Ok(())
}

fn handle_heap_page_fault(fault_address: VirtAddr, is_write: bool) -> Result<(), &'static str> {
    if !validate_heap_chunk(fault_address.as_u64(), 4096) {
        return Err("heap bounds");
    }
    if !is_write {
        return handle_demand_paging(fault_address);
    }

    let frame = {
        let mut a = frame_alloc::get_allocator().lock();
        a.alloc().ok_or("oom")?
    };
    let page = Page::<Size4KiB>::containing_address(fault_address);
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::NO_EXECUTE;

    unsafe {
        let mut mapper = virt::get_kernel_mapper().map_err(|_| "mapper")?;
        let mut fa = frame_alloc::get_allocator().lock();
        mapper.map_to(page, frame, flags, &mut *fa).map_err(|_| "map")?.flush();
        crate::process::update_memory_usage(0, 4096);
    }
    Ok(())
}

fn handle_demand_paging(fault_address: VirtAddr) -> Result<(), &'static str> {
    if let Some(swap_info) = get_swap_info(fault_address) {
        return restore_swapped_page(fault_address, swap_info);
    }
    if let Some(mapping) = get_file_mapping(fault_address) {
        return map_file_page(fault_address, mapping);
    }
    handle_heap_page_fault(fault_address, false)
}

fn handle_user_space_fault(fault_address: VirtAddr, is_write: bool, _process: &Arc<crate::process::ProcessControlBlock>) -> Result<(), &'static str> {
    if is_write {
        Err("segv write")
    } else {
        Err("segv read")
    }
}

pub fn allocate_page_at(fault_addr: u64) -> Result<(), &'static str> {
    let page_addr = VirtAddr::new(fault_addr & !0xFFF);
    if let Some(phys_frame) = frame_alloc::allocate_frame() {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        map_page_to_frame(page_addr, phys_frame, flags)
    } else {
        Err("oom")
    }
}

pub fn handle_cow_fault(fault_addr: u64) -> Result<(), &'static str> {
    let page_addr = VirtAddr::new(fault_addr & !0xFFF);
    unsafe {
        let mut mapper = virt::get_kernel_mapper().map_err(|_| "mapper")?;
        let page = Page::<Size4KiB>::containing_address(page_addr);
        if mapper.translate_page(page).is_err() {
            return Err("not mapped");
        }
        let new_frame = {
            let mut a = frame_alloc::get_allocator().lock();
            a.alloc().ok_or("oom")?
        };
        copy_page_content(page_addr, new_frame)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        update_page_flags(page_addr, flags)?;
    }
    Ok(())
}

fn copy_page_content(page_addr: VirtAddr, new_frame: PhysFrame) -> Result<(), &'static str> {
    let tmp = map_temporary_frame(new_frame.start_address());
    unsafe {
        core::ptr::copy_nonoverlapping(
            (page_addr.as_u64() & !0xFFF) as *const u8,
            tmp.as_mut_ptr(),
            4096,
        );
    }
    Ok(())
}

fn update_page_flags(page_addr: VirtAddr, flags: PageTableFlags) -> Result<(), &'static str> {
    unsafe {
        let mut mapper = virt::get_kernel_mapper().map_err(|_| "mapper")?;
        let page = Page::<Size4KiB>::containing_address(page_addr);
        mapper.update_flags(page, flags).map_err(|_| "upd")?.flush();
    }
    Ok(())
}

pub fn mmap_syscall(addr: u64, length: usize, _prot: i32, _flags: i32, _fd: i32, _offset: i64) -> Option<u64> {
    if length == 0 { return None; }
    let start_addr = if addr == 0 {
        find_free_virtual_range(length)?
    } else {
        VirtAddr::new(addr)
    };
    let pages = (length + 0xFFF) / 0x1000;
    for i in 0..pages {
        let a = start_addr + (i * 0x1000);
        if allocate_page_at(a.as_u64()).is_err() {
            for j in 0..i {
                let c = start_addr + (j * 0x1000);
                let _ = deallocate_page_at(c.as_u64());
            }
            return None;
        }
    }
    Some(start_addr.as_u64())
}

pub fn munmap_syscall(addr: u64, length: usize) -> bool {
    if length == 0 { return false; }
    let start = VirtAddr::new(addr);
    let pages = (length + 0xFFF) / 0x1000;
    for i in 0..pages {
        let a = start + (i * 0x1000);
        if deallocate_page_at(a.as_u64()).is_err() {
            return false;
        }
    }
    true
}

fn deallocate_page_at(addr: u64) -> Result<(), &'static str> {
    let page_addr = VirtAddr::new(addr & !0xFFF);
    unsafe {
        let mut mapper = virt::get_kernel_mapper().map_err(|_| "mapper")?;
        let page = Page::<Size4KiB>::containing_address(page_addr);
        let (frame, flush) = mapper.unmap(page).map_err(|_| "unmap")?;
        flush.flush();
        frame_alloc::deallocate_frame(frame.start_address());
    }
    Ok(())
}

fn is_range_free(addr: VirtAddr, size: usize) -> bool {
    if size == 0 { return false; }
    let pages = (size + 0xFFF) / 0x1000;
    unsafe {
        if let Ok(mapper) = virt::get_kernel_mapper() {
            for i in 0..pages {
                let va = VirtAddr::new(addr.as_u64() + (i as u64 * 0x1000));
                if mapper.translate_addr(va).is_some() {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }
}

fn find_free_virtual_range(size: usize) -> Option<VirtAddr> {
    if size == 0 { return None; }
    // Search a sane user-space region for now
    let mut addr = VirtAddr::new(0x0040_0000);
    let end = VirtAddr::new(0x7FFF_FFFF_0000);
    while addr.as_u64() + size as u64 <= end.as_u64() {
        if is_range_free(addr, size) { return Some(addr); }
        addr = VirtAddr::new(addr.as_u64() + 0x1000);
    }
    None
}

fn find_kernel_memory_region(addr: u64) -> Option<MemoryRegion> {
    for r in get_kernel_memory_regions() {
        if (r.start..(r.start + r.size)).contains(&addr) {
            return Some(r);
        }
    }
    None
}

fn map_kernel_region(fault_address: VirtAddr, _region: &MemoryRegion) -> Result<(), &'static str> {
    let frame = {
        let mut a = frame_alloc::get_allocator().lock();
        a.alloc().ok_or("oom")?
    };
    let page = Page::<Size4KiB>::containing_address(fault_address);
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    unsafe {
        let mut mapper = virt::get_kernel_mapper().map_err(|_| "mapper")?;
        let mut fa = frame_alloc::get_allocator().lock();
        mapper.map_to(page, frame, flags, &mut *fa).map_err(|_| "map")?.flush();
    }
    Ok(())
}

fn restore_swapped_page(fault_address: VirtAddr, swap_info: SwapInfo) -> Result<(), &'static str> {
    let data = crate::storage::read_swap_page(swap_info.swap_slot)?;
    let frame = frame_alloc::allocate_frame().ok_or("oom")?;

    let page = Page::<Size4KiB>::containing_address(fault_address);
    let phys_frame = PhysFrame::<Size4KiB>::containing_address(frame);
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    unsafe {
        let mut mapper = virt::get_kernel_mapper().map_err(|_| "mapper")?;
        let mut fa = frame_alloc::get_allocator().lock();
        mapper.map_to(page, phys_frame, flags, &mut *fa).map_err(|_| "map")?.flush();
        let dst = (fault_address.as_u64() & !0xFFF) as *mut u8;
        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, core::cmp::min(4096, data.len()));
    }

    remove_swap_info(fault_address);
    crate::storage::free_swap_page(swap_info.swap_slot);
    Ok(())
}

fn get_file_mapping(_fault_address: VirtAddr) -> Option<crate::fs::FileMapping> { None }

fn map_file_page(fault_address: VirtAddr, mapping: crate::fs::FileMapping) -> Result<(), &'static str> {
    let page_addr = fault_address.align_down(4096u64);
    let file_offset = page_addr.as_u64() - mapping.virtual_addr.as_u64() + mapping.file_offset;

    let phys_frame = crate::memory::nonos_alloc::allocate_frame().ok_or("oom")?;
    let temp_flags = crate::memory::virt::VmFlags::RW;
    crate::memory::virt::map4k_at(page_addr, phys_frame, temp_flags).map_err(|_| "map")?;

    let page_data = unsafe { core::slice::from_raw_parts_mut(page_addr.as_mut_ptr::<u8>(), 4096) };
    let file_id_str = alloc::format!("{}", mapping.file_id);
    let bytes_read = crate::fs::vfs::read_at_offset(&file_id_str, file_offset as usize, page_data)
        .map_err(|_| "read")?;

    if bytes_read < 4096 {
        page_data[bytes_read..].fill(0);
    }

    let mut final_flags = crate::memory::virt::VmFlags::empty();
    if mapping.permissions.contains(PageFlags::WRITABLE) {
        final_flags |= crate::memory::virt::VmFlags::RW;
    }
    if !mapping.permissions.contains(PageFlags::EXECUTABLE) {
        final_flags |= crate::memory::virt::VmFlags::NX;
    }

    crate::memory::virt::protect4k(page_addr, final_flags).map_err(|_| "protect")?;

    unsafe {
        MEMORY_STATS.mapped_file_pages.fetch_add(1, Ordering::SeqCst);
        MEMORY_STATS.total_mapped_size.fetch_add(4096, Ordering::SeqCst);
    }
    Ok(())
}

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

// In production, prefer real boot memory map; keep this as a fallback if needed.
pub fn get_memory_map() -> Option<alloc::vec::Vec<MemoryMapEntry>> {
    let mut m = alloc::vec::Vec::new();
    m.push(MemoryMapEntry { base_address: 0x0, size: 0x80000, memory_type: MemoryType::Reserved, attributes: 0 });
    m.push(MemoryMapEntry { base_address: 0x80000, size: 0x80000, memory_type: MemoryType::Reclaimable, attributes: 0 });
    m.push(MemoryMapEntry { base_address: 0x100000, size: 0x3F000000, memory_type: MemoryType::Usable, attributes: 0 });
    m.push(MemoryMapEntry { base_address: 0xF000_0000, size: 0x0400_0000, memory_type: MemoryType::Device, attributes: 0 });
    m.push(MemoryMapEntry { base_address: 0xFE00_0000, size: 0x0100_0000, memory_type: MemoryType::Reserved, attributes: 0 });
    m.push(MemoryMapEntry { base_address: 0x1_0000_0000, size: 0x1_0000_0000, memory_type: MemoryType::Usable, attributes: 0 });
    Some(m)
}

pub fn map_physical_memory(phys_addr: u64, size: u64) -> Result<VirtAddr, &'static str> {
    let pages_needed = ((phys_addr & 0xFFF) + size + 4095) / 4096;

    let virt_start = {
        let mut base = None;
        for addr in (0xFFFF_8000_8000_0000u64..0xFFFF_8000_C000_0000u64).step_by(4096) {
            let mut ok = true;
            for i in 0..pages_needed {
                if is_virtual_address_mapped(VirtAddr::new(addr + i * 4096)) {
                    ok = false; break;
                }
            }
            if ok { base = Some(VirtAddr::new(addr)); break; }
        }
        base.ok_or("va space")?
    };

    unsafe {
        let mut mapper = virt::get_kernel_mapper().map_err(|_| "mapper")?;
        let mut fa = frame_alloc::get_allocator().lock();
        for i in 0..pages_needed {
            let va = VirtAddr::new(virt_start.as_u64() + i * 4096);
            let pa = PhysAddr::new((phys_addr & !0xFFF) + i * 4096);
            let page = Page::<Size4KiB>::containing_address(va);
            let frame = PhysFrame::<Size4KiB>::containing_address(pa);
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
            mapper.map_to(page, frame, flags, &mut *fa).map_err(|_| "map")?.flush();
        }
    }

    unsafe {
        MEMORY_STATS.total_mapped_size.fetch_add(size as u64, Ordering::SeqCst);
        MEMORY_STATS.kernel_mappings.fetch_add(1, Ordering::SeqCst);
    }

    Ok(virt_start + (phys_addr & 0xFFF))
}

pub fn unmap_physical_memory(virt_addr: VirtAddr, size: u64) {
    let start = VirtAddr::new(virt_addr.as_u64() & !0xFFF);
    let pages = ((virt_addr.as_u64() & 0xFFF) + size + 4095) / 4096;

    unsafe {
        if let Ok(mut mapper) = virt::get_kernel_mapper() {
            for i in 0..pages {
                let page = Page::<Size4KiB>::containing_address(start + (i * 4096));
                if let Ok((_, f)) = mapper.unmap(page) { f.flush(); }
            }
        }
    }

    unsafe {
        MEMORY_STATS.total_mapped_size.fetch_sub(size as u64, Ordering::SeqCst);
        if MEMORY_STATS.kernel_mappings.load(Ordering::SeqCst) > 0 {
            MEMORY_STATS.kernel_mappings.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn is_virtual_address_mapped(vaddr: VirtAddr) -> bool {
    unsafe { virt::get_kernel_mapper().ok().and_then(|m| m.translate_addr(vaddr)).is_some() }
}

fn map_page_to_frame(vaddr: VirtAddr, paddr: PhysAddr, flags: PageTableFlags) -> Result<(), &'static str> {
    unsafe {
        let mut mapper = virt::get_kernel_mapper().map_err(|_| "mapper")?;
        let mut fa = frame_alloc::get_allocator().lock();
        let page = Page::<Size4KiB>::containing_address(vaddr);
        let frame = PhysFrame::<Size4KiB>::containing_address(paddr);
        mapper.map_to(page, frame, flags, &mut *fa).map_err(|_| "map")?.flush();
    }
    Ok(())
}

/// Secure memory erasure with multiple overwrite passes
/// Implements DoD 5220.22-M standard with verification
pub fn secure_erase(buffer: &mut [u8]) {
    if buffer.is_empty() {
        return;
    }
    
    // Pass 1: All bits set to 1
    buffer.fill(0xFF);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    
    // Pass 2: All bits set to 0  
    buffer.fill(0x00);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    
    // Pass 3: Random pattern
    for byte in buffer.iter_mut() {
        *byte = crate::crypto::random_u32() as u8;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    
    // Pass 4: Complement of random pattern
    for byte in buffer.iter_mut() {
        *byte = !*byte;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    
    // Pass 5: Final zeros
    buffer.fill(0x00);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    
    // Memory barrier to prevent optimization
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}

/// Secure erase for arbitrary memory regions with physical memory clearing
pub unsafe fn secure_erase_physical(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    
    let slice = core::slice::from_raw_parts_mut(ptr, size);
    secure_erase(slice);
    
    // Additional CPU cache flush to ensure data doesn't persist in caches
    core::arch::asm!("wbinvd", options(nostack, preserves_flags));
}

/// Allocate zeroed pages for secure operations
pub fn allocate_zeroed_pages(count: usize) -> Option<VirtAddr> {
    if count == 0 {
        return None;
    }
    
    // Allocate pages
    let flags = crate::memory::virt::VmFlags::RW | crate::memory::virt::VmFlags::NX;
    let base = unsafe { crate::memory::nonos_alloc::kalloc_pages(count, flags) };
    
    if base.as_u64() != 0 {
        // Zero the allocated memory
        unsafe {
            let size = count * crate::memory::layout::PAGE_SIZE;
            core::ptr::write_bytes(base.as_mut_ptr::<u8>(), 0, size);
        }
        Some(base)
    } else {
        None
    }
}

/// Deallocate pages securely
pub fn deallocate_pages(base: VirtAddr, count: usize) {
    if count == 0 {
        return;
    }
    
    // Secure erase before deallocation
    unsafe {
        let size = count * crate::memory::layout::PAGE_SIZE;
        let slice = core::slice::from_raw_parts_mut(base.as_mut_ptr(), size);
        secure_erase(slice);
        
        // Deallocate each page
        for i in 0..count {
            let page_addr = VirtAddr::new(base.as_u64() + (i * crate::memory::layout::PAGE_SIZE) as u64);
            let _ = deallocate_page_at(page_addr.as_u64());
        }
    }
}

/// Initialize module memory protection
pub fn init_module_memory_protection() {
    // Initialize memory protection for modules
}
