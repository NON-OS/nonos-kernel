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

use x86_64::PhysAddr;
// ============================================================================
// ALLOCATION FLAGS
// ============================================================================
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AllocFlags: u32 {
        const EMPTY = 0;
        const ZERO = 1 << 0;
        const HIGH = 1 << 1;
        const DMA = 1 << 2;
        const CONTIGUOUS = 1 << 3;
    }
}

impl Default for AllocFlags {
    fn default() -> Self {
        Self::EMPTY
    }
}
// ============================================================================
// FRAME TYPE
// ============================================================================
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Frame(pub u64);

impl Frame {
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    #[inline]
    pub const fn addr(&self) -> u64 {
        self.0
    }

    #[inline]
    pub fn as_phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.0)
    }

    #[inline]
    pub fn from_phys_addr(addr: PhysAddr) -> Self {
        Self(addr.as_u64())
    }

    #[inline]
    pub const fn number(&self, base: u64, page_size: u64) -> u64 {
        if self.0 < base {
            0
        } else {
            (self.0 - base) / page_size
        }
    }

    #[inline]
    pub const fn is_null(&self) -> bool {
        self.0 == 0
    }
}

impl From<u64> for Frame {
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

impl From<Frame> for u64 {
    fn from(frame: Frame) -> u64 {
        frame.0
    }
}

impl From<PhysAddr> for Frame {
    fn from(addr: PhysAddr) -> Self {
        Self(addr.as_u64())
    }
}

impl From<Frame> for PhysAddr {
    fn from(frame: Frame) -> PhysAddr {
        PhysAddr::new(frame.0)
    }
}

pub type PhysFrame = Frame;
// ============================================================================
// ZONE STATISTICS
// ============================================================================
#[derive(Clone, Copy, Debug, Default)]
pub struct ZoneStats {
    pub frames_total: usize,
    pub frames_free: usize,
}

impl ZoneStats {
    pub const fn new(total: usize, free: usize) -> Self {
        Self {
            frames_total: total,
            frames_free: free,
        }
    }

    pub const fn frames_allocated(&self) -> usize {
        self.frames_total.saturating_sub(self.frames_free)
    }

    pub const fn usage_percent(&self) -> usize {
        if self.frames_total == 0 {
            return 0;
        }
        (self.frames_allocated() * 100) / self.frames_total
    }

    pub const fn total_bytes(&self, page_size: usize) -> usize {
        self.frames_total.saturating_mul(page_size)
    }
    
    pub const fn free_bytes(&self, page_size: usize) -> usize {
        self.frames_free.saturating_mul(page_size)
    }
}
// ============================================================================
// ALLOCATOR STATE
// ============================================================================
#[derive(Debug)]
pub struct AllocatorState {
    pub frame_start: u64,
    pub frame_count: usize,
    pub bitmap_ptr: *mut u8,
    pub bitmap_bytes: usize,
    pub next_hint: u64,
    pub random_seed: u64,
}

impl AllocatorState {
    pub const fn new() -> Self {
        Self {
            frame_start: 0,
            frame_count: 0,
            bitmap_ptr: core::ptr::null_mut(),
            bitmap_bytes: 0,
            next_hint: 0,
            random_seed: 0,
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.frame_count > 0 && !self.bitmap_ptr.is_null()
    }
}

impl Default for AllocatorState {
    fn default() -> Self {
        Self::new()
    }
}
// SAFETY: AllocatorState is protected by a Mutex in the allocator module.
// The raw pointer is only accessed while holding the lock.
unsafe impl Send for AllocatorState {}
unsafe impl Sync for AllocatorState {}
