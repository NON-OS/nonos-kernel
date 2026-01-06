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
use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::vec::Vec;
use x86_64::{PhysAddr, structures::paging::{PhysFrame, Size4KiB, FrameAllocator as X86FrameAllocator}};
use super::constants::*;
use super::error::{FrameAllocError, FrameResult};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRange {
    pub start: PhysAddr,
    pub end: PhysAddr,
}

impl FrameRange {
    pub fn new(start: PhysAddr, end: PhysAddr) -> FrameResult<Self> {
        if start >= end { return Err(FrameAllocError::InvalidRegion); }
        if !start.is_aligned(FRAME_SIZE) || !end.is_aligned(FRAME_SIZE) { return Err(FrameAllocError::RegionNotAligned); }
        Ok(Self { start, end })
    }

    pub fn next_frame(&mut self) -> Option<PhysFrame> {
        let aligned = self.start.align_up(FRAME_SIZE);
        if aligned + FRAME_SIZE <= self.end {
            let frame = PhysFrame::containing_address(aligned);
            self.start = aligned + FRAME_SIZE;
            Some(frame)
        } else { None }
    }

    pub fn frames_remaining(&self) -> usize {
        let aligned_start = self.start.align_up(FRAME_SIZE);
        if aligned_start >= self.end { 0 }
        else { ((self.end.as_u64() - aligned_start.as_u64()) / FRAME_SIZE) as usize }
    }

    pub fn is_exhausted(&self) -> bool { self.frames_remaining() == 0 }
}

pub struct FrameAllocator {
    pub usable: Vec<FrameRange>,
    pub frames_allocated: AtomicUsize,
    pub initialized: bool,
}

impl FrameAllocator {
    pub const fn new() -> Self {
        Self { usable: Vec::new(), frames_allocated: AtomicUsize::new(0), initialized: false }
    }

    pub fn add_region(&mut self, start: PhysAddr, end: PhysAddr) -> FrameResult<()> {
        if self.usable.len() >= MAX_MEMORY_REGIONS { return Err(FrameAllocError::TooManyRegions); }
        let range = FrameRange::new(start, end)?;
        self.usable.push(range);
        Ok(())
    }

    pub fn init(&mut self) -> FrameResult<()> {
        if self.initialized { return Err(FrameAllocError::AlreadyInitialized); }
        if !crate::memory::phys::is_initialized() { return Err(FrameAllocError::PhysAllocatorNotReady); }
        self.initialized = true;
        Ok(())
    }

    pub fn alloc(&mut self) -> Option<PhysFrame> {
        if !self.initialized { return None; }
        if let Some(frame) = crate::memory::phys::alloc(crate::memory::phys::AllocFlags::EMPTY) {
            let phys_frame = PhysFrame::containing_address(PhysAddr::new(frame.0));
            self.frames_allocated.fetch_add(1, Ordering::Relaxed);
            return Some(phys_frame);
        }

        while let Some(range) = self.usable.last_mut() {
            if let Some(frame) = range.next_frame() {
                self.frames_allocated.fetch_add(1, Ordering::Relaxed);
                return Some(frame);
            } else { self.usable.pop(); }
        }
        None
    }

    pub fn dealloc(&self, frame: PhysFrame) -> FrameResult<()> {
        if !self.initialized { return Err(FrameAllocError::NotInitialized); }
        let phys_frame = crate::memory::phys::Frame(frame.start_address().as_u64());
        crate::memory::phys::free(phys_frame).map_err(|_| FrameAllocError::FrameNotAllocated)?;
        self.frames_allocated.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn total_allocated(&self) -> usize { self.frames_allocated.load(Ordering::Relaxed) }
    pub fn regions_available(&self) -> usize { self.usable.len() }
    pub fn is_initialized(&self) -> bool { self.initialized }
    pub fn total_frames_remaining(&self) -> usize { self.usable.iter().map(|r| r.frames_remaining()).sum() }
}

impl Default for FrameAllocator {
    fn default() -> Self { Self::new() }
}

// SAFETY: FrameAllocator returns valid aligned frames, each only once until deallocated
unsafe impl X86FrameAllocator<Size4KiB> for FrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> { self.alloc() }
}
