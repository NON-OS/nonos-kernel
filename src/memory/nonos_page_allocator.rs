//! Page Frame Allocator

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::{
    PhysAddr,
    structures::paging::{FrameAllocator, PhysFrame, Size4KiB},
};

use crate::memory::nonos_phys as phys;

// Expose a stats view compatible with the previous API.
#[derive(Debug, Clone, Copy)]
pub struct FrameAllocatorStats {
    pub total_frames: usize,
    pub allocated_frames: usize,
    pub free_frames: usize,
}

// Global wrapper state (optional counters for compatibility)
struct WrapperStats {
    allocated_frames: AtomicUsize,
}
static WRAP: Mutex<WrapperStats> = Mutex::new(WrapperStats {
    allocated_frames: AtomicUsize::new(0),
});

// Initialize the global frame allocator
// Kept for API compatibility; the real allocator is initialized elsewhere from
// firmware/boot info (nonos_phys::init_from_regions). This is now a no-op.
pub fn init_frame_allocator(_memory_start: PhysAddr, _memory_size: usize) {
    // No-op; production phys allocator is initialized earlier from boot info.
}

// Allocate a physical page frame (4KiB)
pub fn allocate_frame() -> Option<PhysFrame<Size4KiB>> {
    let frame = phys::alloc(phys::AllocFlags::empty())
        .map(|f| PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(f.0)));
    if frame.is_some() {
        WRAP.lock().allocated_frames.fetch_add(1, Ordering::Relaxed);
    }
    frame
}

// Deallocate a physical page frame
pub fn deallocate_frame(frame: PhysFrame<Size4KiB>) {
    phys::free(phys::Frame(frame.start_address().as_u64()));
    WRAP.lock().allocated_frames.fetch_sub(1, Ordering::Relaxed);
}

// Get frame allocator statistics
pub fn get_frame_stats() -> Option<FrameAllocatorStats> {
    // Aggregate across zones exposed by the phys allocator.
    let zs = phys::zone_stats();
    let mut total = 0usize;
    let mut free = 0usize;
    for z in zs {
        total = total.saturating_add(z.total_frames);
        free = free.saturating_add(z.free_frames);
    }
    let alloc = total.saturating_sub(free);
    Some(FrameAllocatorStats {
        total_frames: total,
        allocated_frames: alloc,
        free_frames: free,
    })
}

// Implement x86_64::FrameAllocator using the phys allocator directly.
pub struct PhysFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for PhysFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        allocate_frame()
    }
}
