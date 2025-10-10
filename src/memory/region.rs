//! Memory Region Management
//!
//! Advanced memory region tracking for isolation

use x86_64::VirtAddr;

/// Memory region descriptor
#[derive(Debug, Clone, Copy)]
pub struct MemRegion {
    pub start: u64,
    pub size: usize,
}

impl MemRegion {
    pub fn new(start: u64, size: usize) -> Self {
        Self { start, size }
    }

    pub fn start_addr(&self) -> VirtAddr {
        VirtAddr::new(self.start)
    }

    pub fn end_addr(&self) -> VirtAddr {
        VirtAddr::new(self.start + self.size as u64)
    }

    pub fn size_bytes(&self) -> u64 {
        self.size as u64
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.start + self.size as u64
    }
}
