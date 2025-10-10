// Physical frame allocator over nonos_phys.

use alloc::vec::Vec;
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use crate::memory::nonos_phys as phys;

#[derive(Debug, Clone)]
pub struct FrameRange {
    pub start: PhysAddr,
    pub end: PhysAddr,
}

impl FrameRange {
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

pub struct FrameAllocator {
    usable: Vec<FrameRange>,
    frames_allocated: usize,
}

impl FrameAllocator {
    pub fn new() -> Self {
        Self { usable: Vec::new(), frames_allocated: 0 }
    }

    pub fn add_region(&mut self, start: PhysAddr, end: PhysAddr) {
        self.usable.push(FrameRange { start, end });
    }

    pub fn alloc(&mut self) -> Option<PhysFrame> {
        if let Some(f) = phys::alloc(phys::AllocFlags::empty()) {
            self.frames_allocated += 1;
            let pa = PhysAddr::new(f.0);
            return Some(PhysFrame::containing_address(pa));
        }
        while let Some(r) = self.usable.last_mut() {
            if let Some(fr) = r.next_frame() {
                self.frames_allocated += 1;
                return Some(fr);
            } else {
                self.usable.pop();
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

lazy_static! {
    pub static ref GLOBAL_ALLOCATOR: Mutex<FrameAllocator> = Mutex::new(FrameAllocator::new());
}

pub fn init() {
    // Optional local fallback region (kept for early bring-up where phys isn't ready).
    let mut allocator = GLOBAL_ALLOCATOR.lock();
    if allocator.usable.is_empty() {
        let start = PhysAddr::new(16 * 1024 * 1024);
        let end = PhysAddr::new(512 * 1024 * 1024);
        allocator.add_region(start, end);
    }
}

pub fn alloc_frame() -> Option<PhysFrame> {
    GLOBAL_ALLOCATOR.lock().alloc()
}

pub fn allocate_frame() -> Option<PhysAddr> {
    alloc_frame().map(|f| f.start_address())
}

pub fn deallocate_frame(addr: PhysAddr) {
    phys::free(phys::Frame(addr.as_u64()));
}

pub fn get_stats() -> (usize, usize) {
    let a = GLOBAL_ALLOCATOR.lock();
    (a.total_allocated(), a.regions_available())
}

pub fn get_allocator() -> &'static Mutex<FrameAllocator> {
    &GLOBAL_ALLOCATOR
}

unsafe impl x86_64::structures::paging::FrameAllocator<Size4KiB> for FrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.alloc()
    }
}
