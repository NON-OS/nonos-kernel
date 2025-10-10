//! NØNOS Memory Paging System
//!
//! Sets up basic paging for the kernel with higher-half mapping.

use crate::memory::frame_alloc;
use x86_64::{
    structures::paging::{
        FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame,
        Size4KiB,
    },
    PhysAddr, VirtAddr,
};

/// Virtual offset used for kernel-to-physical mapping (higher half mapping)
const PHYS_MEM_OFFSET: u64 = 0xFFFF800000000000;

/// Simple frame allocator that uses our frame allocator
pub struct SimpleFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for SimpleFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        frame_alloc::alloc_frame()
    }
}

/// Initialize basic paging for the kernel
pub fn init() {
    let phys_offset = VirtAddr::new(PHYS_MEM_OFFSET);
    let level_4_table = unsafe { active_level_4_table(phys_offset) };
    let mut mapper = unsafe { OffsetPageTable::new(level_4_table, phys_offset) };
    let mut frame_allocator = SimpleFrameAllocator;

    // Map essential kernel regions
    map_kernel_identity(&mut mapper, &mut frame_allocator);
}

/// Extracts the active L4 table from CR3 and returns a writable reference
unsafe fn active_level_4_table(phys_offset: VirtAddr) -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;
    let (frame, _) = Cr3::read();
    let phys = frame.start_address().as_u64();
    let virt = phys_offset + phys;
    let table_ptr = virt.as_mut_ptr::<PageTable>();
    &mut *table_ptr
}

/// Identity-maps the static kernel region using 4KiB pages
fn map_kernel_identity(
    mapper: &mut OffsetPageTable,
    allocator: &mut impl FrameAllocator<Size4KiB>,
) {
    // Map the lower 16MB of physical memory for basic kernel operations
    let start_phys = PhysAddr::new(0);
    let end_phys = PhysAddr::new(16 * 1024 * 1024); // 16 MiB

    for frame_addr in (start_phys.as_u64()..end_phys.as_u64()).step_by(4096) {
        let frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(PhysAddr::new(frame_addr));
        let virt = VirtAddr::new(PHYS_MEM_OFFSET + frame_addr);
        let page = Page::containing_address(virt);

        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        unsafe {
            if let Ok(mapping) = mapper.map_to(page, frame, flags, allocator) {
                mapping.flush();
            }
        }
    }
}

/// Helper function to map a single page with given flags
pub unsafe fn map_page(page: Page<Size4KiB>, flags: PageTableFlags) -> Result<(), &'static str> {
    let phys_offset = VirtAddr::new(PHYS_MEM_OFFSET);
    let level_4_table = active_level_4_table(phys_offset);
    let mut mapper = OffsetPageTable::new(level_4_table, phys_offset);
    let mut frame_allocator = SimpleFrameAllocator;

    // Allocate a frame for the page
    let frame = frame_allocator.allocate_frame().ok_or("Failed to allocate frame")?;

    // Map the page to the frame
    mapper
        .map_to(page, frame, flags, &mut frame_allocator)
        .map_err(|_| "Failed to map page")?
        .flush();

    Ok(())
}
