//! Memory allocation utilities

use x86_64::VirtAddr;

pub struct HeapPolicy;

impl HeapPolicy {
    pub fn default() -> Self {
        Self
    }
}

pub fn init(_policy: HeapPolicy) {
    // Stub implementation
}

pub fn allocate_kernel_pages(_size: u64) -> Option<VirtAddr> {
    // Stub implementation
    None
}
