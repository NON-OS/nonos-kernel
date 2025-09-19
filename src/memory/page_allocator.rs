//! Production Page Frame Allocator
//!
//! Manages physical page allocation for kernel and user space

use x86_64::{PhysAddr, structures::paging::{PhysFrame, Size4KiB, FrameAllocator}};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
use alloc::vec::Vec;

/// Page frame size (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Maximum supported physical memory (1GB for now)
const MAX_MEMORY: usize = 1024 * 1024 * 1024; 
const MAX_FRAMES: usize = MAX_MEMORY / PAGE_SIZE;

/// Bitmap-based page frame allocator
pub struct BitmapFrameAllocator {
    bitmap: Vec<u8>,
    start_frame: PhysFrame<Size4KiB>,
    total_frames: usize,
    allocated_frames: AtomicUsize,
}

impl BitmapFrameAllocator {
    /// Create new frame allocator
    pub fn new(start_addr: PhysAddr, memory_size: usize) -> Self {
        let start_frame = PhysFrame::containing_address(start_addr);
        let total_frames = memory_size / PAGE_SIZE;
        let bitmap_size = (total_frames + 7) / 8; // Round up to nearest byte
        
        let mut bitmap = Vec::with_capacity(bitmap_size);
        bitmap.resize(bitmap_size, 0);
        
        BitmapFrameAllocator {
            bitmap,
            start_frame,
            total_frames,
            allocated_frames: AtomicUsize::new(0),
        }
    }
    
    /// Initialize with kernel memory regions marked as allocated
    pub fn init_kernel_regions(&mut self, kernel_start: PhysAddr, kernel_end: PhysAddr) {
        let start_frame_idx = self.frame_to_index(PhysFrame::containing_address(kernel_start));
        let end_frame_idx = self.frame_to_index(PhysFrame::containing_address(kernel_end));
        
        for i in start_frame_idx..=end_frame_idx {
            self.set_allocated(i);
        }
    }
    
    /// Mark multiboot regions as allocated
    pub fn mark_multiboot_regions(&mut self, _multiboot_start: PhysAddr, _multiboot_end: PhysAddr) {
        // TODO: Parse multiboot memory map and mark reserved regions
        // For now, just mark the first MB as reserved (BIOS/bootloader stuff)
        let reserved_frames = (1024 * 1024) / PAGE_SIZE; // First 1MB
        for i in 0..reserved_frames {
            if i < self.total_frames {
                self.set_allocated(i);
            }
        }
    }
    
    /// Convert frame to bitmap index
    fn frame_to_index(&self, frame: PhysFrame<Size4KiB>) -> usize {
        let frame_num = (frame.start_address().as_u64() - self.start_frame.start_address().as_u64()) 
            / PAGE_SIZE as u64;
        frame_num as usize
    }
    
    /// Convert bitmap index to frame
    fn index_to_frame(&self, index: usize) -> PhysFrame<Size4KiB> {
        let addr = self.start_frame.start_address().as_u64() + (index * PAGE_SIZE) as u64;
        PhysFrame::containing_address(PhysAddr::new(addr))
    }
    
    /// Check if frame is allocated
    fn is_allocated(&self, index: usize) -> bool {
        if index >= self.total_frames {
            return true; // Out of range = allocated
        }
        let byte_index = index / 8;
        let bit_index = index % 8;
        if byte_index < self.bitmap.len() {
            (self.bitmap[byte_index] >> bit_index) & 1 != 0
        } else {
            true
        }
    }
    
    /// Set frame as allocated
    fn set_allocated(&mut self, index: usize) {
        if index >= self.total_frames {
            return;
        }
        let byte_index = index / 8;
        let bit_index = index % 8;
        if byte_index < self.bitmap.len() {
            if (self.bitmap[byte_index] >> bit_index) & 1 == 0 {
                self.bitmap[byte_index] |= 1 << bit_index;
                self.allocated_frames.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    
    /// Set frame as free
    fn set_free(&mut self, index: usize) {
        if index >= self.total_frames {
            return;
        }
        let byte_index = index / 8;
        let bit_index = index % 8;
        if byte_index < self.bitmap.len() {
            if (self.bitmap[byte_index] >> bit_index) & 1 != 0 {
                self.bitmap[byte_index] &= !(1 << bit_index);
                self.allocated_frames.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    
    /// Find next free frame
    fn find_free_frame(&self) -> Option<usize> {
        for (byte_index, &byte) in self.bitmap.iter().enumerate() {
            if byte != 0xFF { // Not all bits set
                for bit_index in 0..8 {
                    let frame_index = byte_index * 8 + bit_index;
                    if frame_index >= self.total_frames {
                        return None;
                    }
                    if (byte >> bit_index) & 1 == 0 {
                        return Some(frame_index);
                    }
                }
            }
        }
        None
    }
    
    /// Get allocation statistics
    pub fn get_stats(&self) -> FrameAllocatorStats {
        FrameAllocatorStats {
            total_frames: self.total_frames,
            allocated_frames: self.allocated_frames.load(Ordering::Relaxed),
            free_frames: self.total_frames - self.allocated_frames.load(Ordering::Relaxed),
        }
    }
}

unsafe impl FrameAllocator<Size4KiB> for BitmapFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        if let Some(index) = self.find_free_frame() {
            self.set_allocated(index);
            Some(self.index_to_frame(index))
        } else {
            None
        }
    }
}

/// Frame allocator statistics
#[derive(Debug, Clone, Copy)]
pub struct FrameAllocatorStats {
    pub total_frames: usize,
    pub allocated_frames: usize,
    pub free_frames: usize,
}

/// Global frame allocator
static FRAME_ALLOCATOR: Mutex<Option<BitmapFrameAllocator>> = Mutex::new(None);

/// Initialize the global frame allocator
pub fn init_frame_allocator(memory_start: PhysAddr, memory_size: usize) {
    let mut allocator = BitmapFrameAllocator::new(memory_start, memory_size);
    
    // Mark kernel regions as allocated
    let kernel_start = PhysAddr::new(0x100000); // 1MB where kernel is loaded
    let kernel_end = PhysAddr::new(0x400000);   // 4MB assumed kernel size
    allocator.init_kernel_regions(kernel_start, kernel_end);
    
    // Mark multiboot and BIOS regions
    allocator.mark_multiboot_regions(PhysAddr::new(0), PhysAddr::new(1024 * 1024));
    
    *FRAME_ALLOCATOR.lock() = Some(allocator);
}

/// Allocate a physical page frame
pub fn allocate_frame() -> Option<PhysFrame<Size4KiB>> {
    FRAME_ALLOCATOR.lock().as_mut()?.allocate_frame()
}

/// Deallocate a physical page frame
pub fn deallocate_frame(frame: PhysFrame<Size4KiB>) {
    if let Some(ref mut allocator) = *FRAME_ALLOCATOR.lock() {
        let index = allocator.frame_to_index(frame);
        allocator.set_free(index);
    }
}

/// Get frame allocator statistics
pub fn get_frame_stats() -> Option<FrameAllocatorStats> {
    FRAME_ALLOCATOR.lock().as_ref().map(|a| a.get_stats())
}