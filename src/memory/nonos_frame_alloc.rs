#![no_std]

use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::{PhysAddr, structures::paging::{PhysFrame, Size4KiB, FrameAllocator as X86FrameAllocator}};
use crate::memory::nonos_phys as phys;

pub struct FrameRange {
    pub start: PhysAddr,
    pub end: PhysAddr,
}

impl FrameRange {
    pub fn next_frame(&mut self) -> Option<PhysFrame> {
        let aligned = self.start.align_up(4096u64);
        if aligned + 4096u64 <= self.end {
            let frame = PhysFrame::containing_address(aligned);
            self.start = aligned + 4096u64;
            Some(frame)
        } else {
            None
        }
    }
}

pub struct FrameAllocator {
    usable: Vec<FrameRange>,
    frames_allocated: AtomicUsize,
    initialized: bool,
}

impl FrameAllocator {
    pub fn new() -> Self {
        Self { 
            usable: Vec::new(), 
            frames_allocated: AtomicUsize::new(0),
            initialized: false,
        }
    }

    pub fn add_region(&mut self, start: PhysAddr, end: PhysAddr) -> Result<(), &'static str> {
        if start >= end {
            return Err("Invalid region: start >= end");
        }
        
        if start.as_u64() % 4096 != 0 || end.as_u64() % 4096 != 0 {
            return Err("Region boundaries must be page-aligned");
        }
        
        self.usable.push(FrameRange { start, end });
        Ok(())
    }

    pub fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized {
            return Err("Frame allocator already initialized");
        }
        
        if !phys::is_initialized() {
            return Err("Physical memory allocator not initialized");
        }
        
        self.initialized = true;
        Ok(())
    }

    pub fn alloc(&mut self) -> Option<PhysFrame> {
        if !self.initialized {
            return None;
        }
        
        if let Some(frame) = phys::alloc(phys::AllocFlags::EMPTY) {
            let phys_frame = PhysFrame::containing_address(PhysAddr::new(frame.0));
            self.frames_allocated.fetch_add(1, Ordering::Relaxed);
            return Some(phys_frame);
        }
        
        while let Some(range) = self.usable.last_mut() {
            if let Some(frame) = range.next_frame() {
                self.frames_allocated.fetch_add(1, Ordering::Relaxed);
                return Some(frame);
            } else {
                self.usable.pop();
            }
        }
        
        None
    }

    pub fn dealloc(&self, frame: PhysFrame) -> Result<(), &'static str> {
        if !self.initialized {
            return Err("Frame allocator not initialized");
        }
        
        let phys_frame = phys::Frame(frame.start_address().as_u64());
        phys::free(phys_frame)?;
        
        self.frames_allocated.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn total_allocated(&self) -> usize {
        self.frames_allocated.load(Ordering::Relaxed)
    }

    pub fn regions_available(&self) -> usize {
        self.usable.len()
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

static GLOBAL_ALLOCATOR: Mutex<FrameAllocator> = Mutex::new(FrameAllocator {
    usable: Vec::new(),
    frames_allocated: AtomicUsize::new(0),
    initialized: false,
});

pub fn init() -> Result<(), &'static str> {
    let mut allocator = GLOBAL_ALLOCATOR.lock();
    
    if allocator.is_initialized() {
        return Ok(());
    }
    
    allocator.init()?;
    
    if allocator.usable.is_empty() {
        let start = PhysAddr::new(16 * 1024 * 1024);  // 16MB
        let end = PhysAddr::new(512 * 1024 * 1024);   // 512MB
        allocator.add_region(start, end)?;
    }
    
    Ok(())
}

pub fn alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    GLOBAL_ALLOCATOR.lock().alloc()
}

pub fn allocate_frame() -> Option<PhysAddr> {
    alloc_frame().map(|f| f.start_address())
}

pub fn deallocate_frame(addr: PhysAddr) -> Result<(), &'static str> {
    let frame = PhysFrame::containing_address(addr);
    GLOBAL_ALLOCATOR.lock().dealloc(frame)
}

pub fn get_stats() -> (usize, usize) {
    let allocator = GLOBAL_ALLOCATOR.lock();
    (allocator.total_allocated(), allocator.regions_available())
}

pub fn get_allocator() -> &'static Mutex<FrameAllocator> {
    &GLOBAL_ALLOCATOR
}

pub fn add_memory_region(start: PhysAddr, end: PhysAddr) -> Result<(), &'static str> {
    GLOBAL_ALLOCATOR.lock().add_region(start, end)
}

pub fn total_free_frames() -> usize {
    phys::total_free_frames()
}

unsafe impl X86FrameAllocator<Size4KiB> for FrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.alloc()
    }
}