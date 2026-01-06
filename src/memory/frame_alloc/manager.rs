// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use spin::Mutex;
use x86_64::{PhysAddr, structures::paging::{PhysFrame, Size4KiB}};
use crate::memory::phys;
use super::constants::*;
use super::error::{FrameAllocError, FrameResult};
use super::types::FrameAllocator;
static GLOBAL_ALLOCATOR: Mutex<FrameAllocator> = Mutex::new(FrameAllocator::new());
pub fn init() -> FrameResult<()> {
    let mut allocator = GLOBAL_ALLOCATOR.lock();
    if allocator.is_initialized() { return Ok(()); }
    allocator.init()?;
    if allocator.usable.is_empty() {
        let start = PhysAddr::new(DEFAULT_REGION_START);
        let end = PhysAddr::new(DEFAULT_REGION_END);
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

pub fn deallocate_frame(addr: PhysAddr) -> FrameResult<()> {
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

pub fn add_memory_region(start: PhysAddr, end: PhysAddr) -> FrameResult<()> {
    GLOBAL_ALLOCATOR.lock().add_region(start, end)
}

pub fn total_free_frames() -> usize {
    phys::total_free_frames()
}

pub fn is_initialized() -> bool {
    GLOBAL_ALLOCATOR.lock().is_initialized()
}
