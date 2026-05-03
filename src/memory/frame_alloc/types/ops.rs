// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use super::super::error::{FrameAllocError, FrameResult};
use super::allocator::FrameAllocator;
use crate::memory::addr::PhysAddr;
use core::sync::atomic::Ordering;
use x86_64::structures::paging::{FrameAllocator as X86FrameAllocator, PhysFrame, Size4KiB};

impl FrameAllocator {
    pub fn alloc(&mut self) -> Option<PhysFrame> {
        if !self.initialized {
            return None;
        }

        if let Some(frame) = crate::memory::phys::alloc(crate::memory::phys::AllocFlags::EMPTY) {
            let phys_frame = PhysFrame::containing_address(x86_64::PhysAddr::new(frame.0));
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

    pub fn dealloc(&self, frame: PhysFrame) -> FrameResult<()> {
        if !self.initialized {
            return Err(FrameAllocError::NotInitialized);
        }
        let phys_frame = crate::memory::phys::Frame(frame.start_address().as_u64());
        crate::memory::phys::free(phys_frame).map_err(|_| FrameAllocError::FrameNotAllocated)?;
        self.frames_allocated.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }
}

unsafe impl X86FrameAllocator<Size4KiB> for FrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.alloc()
    }
}
