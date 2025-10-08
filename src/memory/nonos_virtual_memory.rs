//! Virtual Memory Management
//!
//! Production-ready virtual memory management with proper paging

use x86_64::{
    VirtAddr, PhysAddr,
    structures::paging::{
        PageTable, PageTableFlags, OffsetPageTable, Mapper, 
        Size4KiB, Page, PhysFrame
    },
    registers::control::Cr3,
};
use crate::memory::page_allocator::{allocate_frame, deallocate_frame};
use spin::Mutex;
use alloc::format;

/// Virtual memory manager
pub struct VirtualMemoryManager {
    mapper: OffsetPageTable<'static>,
    physical_offset: VirtAddr,
}

impl VirtualMemoryManager {
    /// Create new virtual memory manager
    pub unsafe fn new(physical_offset: VirtAddr) -> Self {
        let level_4_table = active_level_4_table(physical_offset);
        let mapper = OffsetPageTable::new(level_4_table, physical_offset);
        
        VirtualMemoryManager {
            mapper,
            physical_offset,
        }
    }
    
    /// Map a virtual page to a physical frame
    pub fn map_page(
        &mut self,
        page: Page<Size4KiB>,
        frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        let mut frame_allocator = FrameAllocatorWrapper;
        
        match unsafe { self.mapper.map_to(page, frame, flags, &mut frame_allocator) } {
            Ok(flush) => {
                flush.flush();
                Ok(())
            },
            Err(e) => {
                crate::log::logger::log_critical(&format!("Failed to map page: {:?}", e));
                Err("Failed to map page")
            }
        }
    }
    
    /// Unmap a virtual page
    pub fn unmap_page(&mut self, page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, &'static str> {
        match self.mapper.unmap(page) {
            Ok((frame, flush)) => {
                flush.flush();
                Ok(frame)
            },
            Err(_) => Err("Failed to unmap page")
        }
    }
    
    /// Get physical address for virtual address
    pub fn translate_addr(&self, addr: VirtAddr) -> Option<PhysAddr> {
        use x86_64::structures::paging::mapper::{Translate, TranslateResult};
        match self.mapper.translate(addr) {
            TranslateResult::Mapped { frame, offset, .. } => Some(frame.start_address() + offset),
            _ => None,
        }
    }
    
    /// Map multiple contiguous pages
    pub fn map_range(
        &mut self,
        start_page: Page<Size4KiB>,
        start_frame: PhysFrame<Size4KiB>,
        page_count: usize,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        for i in 0..page_count {
            let page = start_page + i as u64;
            let frame = start_frame + i as u64;
            
            self.map_page(page, frame, flags)?;
        }
        Ok(())
    }
    
    /// Create identity mapping for a physical range
    pub fn identity_map_range(
        &mut self,
        start_addr: PhysAddr,
        size: usize,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        let start_frame = PhysFrame::containing_address(start_addr);
        let start_page = Page::containing_address(VirtAddr::new(start_addr.as_u64()));
        let page_count = (size + 4095) / 4096; // Round up to page boundary
        
        self.map_range(start_page, start_frame, page_count, flags)
    }
    
    /// Create higher-half mapping
    pub fn higher_half_map_range(
        &mut self,
        phys_start: PhysAddr,
        virt_start: VirtAddr,
        size: usize,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        let start_frame = PhysFrame::containing_address(phys_start);
        let start_page = Page::containing_address(virt_start);
        let page_count = (size + 4095) / 4096;
        
        self.map_range(start_page, start_frame, page_count, flags)
    }
}

/// Frame allocator wrapper for the mapper
struct FrameAllocatorWrapper;

unsafe impl x86_64::structures::paging::FrameAllocator<Size4KiB> for FrameAllocatorWrapper {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        allocate_frame()
    }
}

/// Get active level 4 page table
unsafe fn active_level_4_table(physical_offset: VirtAddr) -> &'static mut PageTable {
    let (level_4_table_frame, _) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = physical_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();
    &mut *page_table_ptr
}

/// Global virtual memory manager
static VMEM_MANAGER: Mutex<Option<VirtualMemoryManager>> = Mutex::new(None);

/// Initialize virtual memory management
pub fn init_virtual_memory() -> Result<(), &'static str> {
    let physical_offset = VirtAddr::new(0xFFFF800000000000); // Higher half
    
    let mut manager = unsafe { VirtualMemoryManager::new(physical_offset) };
    
    // Set up essential kernel mappings
    setup_kernel_mappings(&mut manager)?;
    
    *VMEM_MANAGER.lock() = Some(manager);
    
    Ok(())
}

/// Set up essential kernel virtual memory mappings
fn setup_kernel_mappings(manager: &mut VirtualMemoryManager) -> Result<(), &'static str> {
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    
    // Identity map VGA buffer
    manager.identity_map_range(
        PhysAddr::new(0xb8000),
        4096,
        flags,
    )?;
    
    // Identity map first 16MB (kernel space)
    manager.identity_map_range(
        PhysAddr::new(0),
        16 * 1024 * 1024,
        flags,
    )?;
    
    // Map kernel heap region
    let heap_start = crate::memory::heap::HEAP_START as u64;
    let heap_size = crate::memory::heap::HEAP_SIZE;
    
    // Allocate physical frames for heap
    let heap_pages = (heap_size + 4095) / 4096;
    let heap_virt_start = VirtAddr::new(heap_start);
    
    for i in 0..heap_pages {
        if let Some(frame) = allocate_frame() {
            let page = Page::containing_address(heap_virt_start + (i * 4096) as u64);
            manager.map_page(page, frame, flags)?;
        } else {
            return Err("Failed to allocate frames for kernel heap");
        }
    }
    
    Ok(())
}

/// Map a virtual address range
pub fn map_memory_range(
    virt_addr: VirtAddr,
    phys_addr: PhysAddr,
    size: usize,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    if let Some(ref mut vmem) = *manager {
        vmem.higher_half_map_range(phys_addr, virt_addr, size, flags)
    } else {
        Err("Virtual memory manager not initialized")
    }
}

/// Unmap a virtual address range
pub fn unmap_memory_range(virt_addr: VirtAddr, size: usize) -> Result<(), &'static str> {
    let mut manager = VMEM_MANAGER.lock();
    if let Some(ref mut vmem) = *manager {
        let start_page = Page::containing_address(virt_addr);
        let page_count = (size + 4095) / 4096;
        
        for i in 0..page_count {
            let page = start_page + i as u64;
            match vmem.unmap_page(page) {
                Ok(frame) => {
                    deallocate_frame(frame);
                },
                Err(_) => return Err("Failed to unmap page"),
            }
        }
        Ok(())
    } else {
        Err("Virtual memory manager not initialized")
    }
}

/// Translate virtual address to physical
pub fn translate_virtual_address(virt_addr: VirtAddr) -> Option<PhysAddr> {
    let manager = VMEM_MANAGER.lock();
    manager.as_ref()?.translate_addr(virt_addr)
}

/// Check if address is mapped
pub fn is_mapped(virt_addr: VirtAddr) -> bool {
    translate_virtual_address(virt_addr).is_some()
}