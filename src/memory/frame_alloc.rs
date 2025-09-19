//! NØNOS Physical Frame Allocator
//!
//! Provides physical memory frame allocation for the ZeroState runtime. Uses UEFI bootloader memory map
//! to establish ownership of `CONVENTIONAL` RAM regions, which are identity-safe and aligned for 4KiB paging.
//!
//! This allocator supports:
//! - Alignment-aware frame extraction
//! - Lazy bump-pointer strategy with multiple memory zones
//! - Integration with heap, paging, and module sandboxes
//! - Optional extension to buddy systems, slab, or zone-based policies

use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::PhysAddr;
use alloc::vec::Vec;

/// A range of physical memory available for frame allocation
#[derive(Debug, Clone)]
pub struct FrameRange {
    pub start: PhysAddr,
    pub end: PhysAddr,
}

impl FrameRange {
    /// Returns aligned next usable frame if available
    pub fn next_frame(&mut self) -> Option<PhysFrame> {
        let next_aligned = self.start.align_up(4096u64);
        if next_aligned + 4096u64 <= self.end {
            self.start = next_aligned + 4096u64;
            Some(PhysFrame::containing_address(next_aligned))
        } else {
            None
        }
    }
}

/// Core frame allocator managing physical memory pool
pub struct FrameAllocator {
    usable: Vec<FrameRange>,
    next: usize,
    frames_allocated: usize,
}

impl FrameAllocator {
    pub fn new() -> Self {
        FrameAllocator {
            usable: Vec::new(),
            next: 0,
            frames_allocated: 0,
        }
    }

    pub fn add_region(&mut self, start: PhysAddr, end: PhysAddr) {
        self.usable.push(FrameRange { start, end });
    }

    pub fn alloc(&mut self) -> Option<PhysFrame> {
        while self.next < self.usable.len() {
            if let Some(frame) = self.usable[self.next].next_frame() {
                self.frames_allocated += 1;
                return Some(frame);
            } else {
                self.next += 1;
            }
        }
        None
    }

    pub fn total_allocated(&self) -> usize {
        self.frames_allocated
    }

    pub fn regions_available(&self) -> usize {
        self.usable.len()
    }
}

lazy_static::lazy_static! {
    /// Singleton access to the global allocator instance
    pub static ref GLOBAL_ALLOCATOR: Mutex<FrameAllocator> = Mutex::new(FrameAllocator::new());
}

/// Initialize with a simple fixed memory region for now
pub fn init() {
    let mut allocator = GLOBAL_ALLOCATOR.lock();
    // Reserve 16MB-512MB for kernel frames (avoiding low memory)
    let start = PhysAddr::new(16 * 1024 * 1024);  // 16MB
    let end = PhysAddr::new(512 * 1024 * 1024);   // 512MB
    allocator.add_region(start, end);
    log_allocator_status("[ALLOC] Frame allocator initialized with 496MB.");
}

/// Public allocation interface
pub fn alloc_frame() -> Option<PhysFrame> {
    GLOBAL_ALLOCATOR.lock().alloc()
}

/// Allocate a physical frame and return PhysAddr
pub fn allocate_frame() -> Option<PhysAddr> {
    alloc_frame().map(|frame| frame.start_address())
}

/// Deallocate a physical frame
pub fn deallocate_frame(addr: PhysAddr) {
    // TODO: Implement proper deallocation with free list
    // For now, this is a no-op as we use a bump allocator
}

/// Get frame allocator statistics
pub fn get_stats() -> (usize, usize) {
    let allocator = GLOBAL_ALLOCATOR.lock();
    (allocator.total_allocated(), allocator.regions_available())
}

/// Get global allocator for advanced memory management
pub fn get_allocator() -> &'static Mutex<FrameAllocator> {
    &GLOBAL_ALLOCATOR
}

/// Simple log interface (safe for early boot)
fn log_allocator_status(msg: &str) {
    if let Some(logger) = crate::log::logger::try_get_logger() {
        logger.log(msg);
    } else {
        let vga = 0xb8000 as *mut u8;
        for (i, byte) in msg.bytes().enumerate().take(80) {
            unsafe {
                *vga.offset(i as isize * 2) = byte;
            }
        }
    }
}

/// Implement x86_64 FrameAllocator trait for our FrameAllocator
unsafe impl x86_64::structures::paging::FrameAllocator<Size4KiB> for FrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.alloc()
    }
}
