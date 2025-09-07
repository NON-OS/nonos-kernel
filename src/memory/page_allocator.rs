//! Page allocation module

use crate::memory::phys::Frame;

pub const PAGE_SIZE: u32 = 4096;

pub fn allocate_frame() -> Option<Frame> {
    // Stub implementation
    None
}
