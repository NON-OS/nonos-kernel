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

use super::super::constants::MAX_MEMORY_REGIONS;
use super::super::error::{FrameAllocError, FrameResult};
use super::range::FrameRange;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::memory::addr::PhysAddr;

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
        if self.usable.len() >= MAX_MEMORY_REGIONS {
            return Err(FrameAllocError::TooManyRegions);
        }
        let range = FrameRange::new(start, end)?;
        self.usable.push(range);
        Ok(())
    }

    pub fn init(&mut self) -> FrameResult<()> {
        if self.initialized {
            return Err(FrameAllocError::AlreadyInitialized);
        }
        self.initialized = true;
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
    pub fn total_frames_remaining(&self) -> usize {
        self.usable.iter().map(|r| r.frames_remaining()).sum()
    }
}

impl Default for FrameAllocator {
    fn default() -> Self {
        Self::new()
    }
}
