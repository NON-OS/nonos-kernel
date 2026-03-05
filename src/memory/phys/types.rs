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

//! Physical Memory Allocator Types

use x86_64::PhysAddr;

// ============================================================================
// ALLOCATION FLAGS
// ============================================================================

bitflags::bitflags! {
    /// Flags for physical frame allocation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AllocFlags: u32 {
        /// No special flags
        const EMPTY = 0;
        /// Zero the allocated frame(s)
        const ZERO = 1 << 0;
        /// Allocate from high memory first
        const HIGH = 1 << 1;
        /// Allocation is for DMA (low memory preferred)
        const DMA = 1 << 2;
        /// Allocation must be physically contiguous
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

/// A physical memory frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Frame(pub u64);

impl Frame {
    /// Creates a new frame from a physical address.
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Returns the physical address of this frame.
    #[inline]
    pub const fn addr(&self) -> u64 {
        self.0
    }

    /// Returns the frame as a PhysAddr.
    #[inline]
    pub fn as_phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.0)
    }

    /// Creates a frame from a PhysAddr.
    #[inline]
    pub fn from_phys_addr(addr: PhysAddr) -> Self {
        Self(addr.as_u64())
    }

    /// Returns the frame number (index).
    #[inline]
    pub const fn number(&self, base: u64, page_size: u64) -> u64 {
        if self.0 < base {
            0
        } else {
            (self.0 - base) / page_size
        }
    }

    /// Checks if this frame is null (address 0).
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

/// Type alias for API compatibility.
pub type PhysFrame = Frame;

// ============================================================================
// ZONE STATISTICS
// ============================================================================

/// Statistics for a memory zone.
#[derive(Clone, Copy, Debug, Default)]
pub struct ZoneStats {
    /// Total frames in this zone
    pub frames_total: usize,
    /// Free frames in this zone
    pub frames_free: usize,
}

impl ZoneStats {
    /// Creates new zone statistics.
    pub const fn new(total: usize, free: usize) -> Self {
        Self {
            frames_total: total,
            frames_free: free,
        }
    }

    /// Returns the number of allocated frames.
    pub const fn frames_allocated(&self) -> usize {
        self.frames_total.saturating_sub(self.frames_free)
    }

    /// Returns the usage percentage (0-100).
    pub const fn usage_percent(&self) -> usize {
        if self.frames_total == 0 {
            return 0;
        }
        (self.frames_allocated() * 100) / self.frames_total
    }

    /// Returns total bytes in this zone.
    pub const fn total_bytes(&self, page_size: usize) -> usize {
        self.frames_total.saturating_mul(page_size)
    }

    /// Returns free bytes in this zone.
    pub const fn free_bytes(&self, page_size: usize) -> usize {
        self.frames_free.saturating_mul(page_size)
    }
}

// ============================================================================
// ALLOCATOR STATE
// ============================================================================

/// Internal state for the physical allocator.
#[derive(Debug)]
pub struct AllocatorState {
    /// Start of managed physical memory
    pub frame_start: u64,
    /// Number of managed frames
    pub frame_count: usize,
    /// Pointer to allocation bitmap
    pub bitmap_ptr: *mut u8,
    /// Size of bitmap in bytes
    pub bitmap_bytes: usize,
    /// Hint for next allocation search
    pub next_hint: u64,
    /// Random seed for allocation randomization
    pub random_seed: u64,
}

impl AllocatorState {
    /// Creates uninitialized state.
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

    /// Checks if the allocator is initialized.
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
