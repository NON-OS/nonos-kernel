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

//! Region Types

use x86_64::VirtAddr;

use super::constants::*;

// ============================================================================
// REGION TYPE
// ============================================================================

/// Type of memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegionType {
    /// Available for allocation
    Available,
    /// Reserved (not usable)
    Reserved,
    /// Kernel code and data
    Kernel,
    /// User space
    User,
    /// Stack
    Stack,
    /// Heap
    Heap,
    /// Memory-mapped I/O
    Mmio,
    /// Firmware reserved
    Firmware,
    /// Bootloader reserved
    Bootloader,
    /// DMA buffer
    Dma,
    /// Guard page
    Guard,
    /// Shared memory
    Shared,
}

impl RegionType {
    /// Returns true if this region type is allocatable.
    pub const fn is_allocatable(&self) -> bool {
        matches!(self, Self::Available)
    }

    /// Returns true if this is a kernel region type.
    pub const fn is_kernel(&self) -> bool {
        matches!(self, Self::Kernel | Self::Stack | Self::Heap)
    }

    /// Returns true if this is a reserved region type.
    pub const fn is_reserved(&self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Firmware | Self::Bootloader | Self::Guard
        )
    }
}

impl Default for RegionType {
    fn default() -> Self {
        Self::Available
    }
}

// ============================================================================
// REGION FLAGS
// ============================================================================

/// Flags for memory regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionFlags {
    /// Region is readable
    Readable,
    /// Region is writable
    Writable,
    /// Region is executable
    Executable,
    /// Region is cacheable
    Cacheable,
    /// Region is shared
    Shared,
    /// Region is locked (pinned)
    Locked,
    /// Region is protected
    Protected,
    /// Region is encrypted
    Encrypted,
}

impl RegionFlags {
    /// Returns the bit value for this flag.
    pub const fn bit(&self) -> u32 {
        match self {
            Self::Readable => FLAG_READABLE,
            Self::Writable => FLAG_WRITABLE,
            Self::Executable => FLAG_EXECUTABLE,
            Self::Cacheable => FLAG_CACHEABLE,
            Self::Shared => FLAG_SHARED,
            Self::Locked => FLAG_LOCKED,
            Self::Protected => FLAG_PROTECTED,
            Self::Encrypted => FLAG_ENCRYPTED,
        }
    }
}

// ============================================================================
// MEMORY REGION
// ============================================================================

/// A memory region descriptor.
#[derive(Debug, Clone, Copy)]
pub struct MemRegion {
    /// Start address
    pub start: u64,
    /// Size in bytes
    pub size: usize,
    /// Region type
    pub region_type: RegionType,
    /// Flags (bitfield)
    pub flags: u32,
    /// Creation timestamp
    pub creation_time: u64,
    /// Access count
    pub access_count: u64,
}

impl MemRegion {
    /// Creates a new memory region.
    pub const fn new(start: u64, size: usize, region_type: RegionType) -> Self {
        Self {
            start,
            size,
            region_type,
            flags: 0,
            creation_time: 0,
            access_count: 0,
        }
    }

    /// Returns start address as VirtAddr.
    pub fn start_addr(&self) -> VirtAddr {
        VirtAddr::new(self.start)
    }

    /// Returns end address (exclusive).
    pub const fn end(&self) -> u64 {
        self.start + self.size as u64
    }

    /// Returns end address as VirtAddr.
    pub fn end_addr(&self) -> VirtAddr {
        VirtAddr::new(self.end())
    }

    /// Returns size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.size as u64
    }

    /// Returns true if address is within this region.
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }

    /// Returns true if another region is entirely within this one.
    pub const fn contains_range(&self, other: &MemRegion) -> bool {
        other.start >= self.start && other.end() <= self.end()
    }

    /// Returns true if regions overlap.
    pub const fn overlaps(&self, other: &MemRegion) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    /// Returns true if region has the specified flag.
    pub fn has_flag(&self, flag: RegionFlags) -> bool {
        (self.flags & flag.bit()) != 0
    }

    /// Sets a flag on this region.
    pub fn set_flag(&mut self, flag: RegionFlags) {
        self.flags |= flag.bit();
    }

    /// Clears a flag on this region.
    pub fn clear_flag(&mut self, flag: RegionFlags) {
        self.flags &= !flag.bit();
    }

    /// Computes union of two regions if possible.
    pub fn union(&self, other: &MemRegion) -> Option<MemRegion> {
        if self.region_type != other.region_type {
            return None;
        }

        // Check for adjacency or overlap
        if self.end() < other.start && other.end() < self.start {
            // Only merge if exactly adjacent
            if self.end() != other.start && other.end() != self.start {
                return None;
            }
        }

        let lo = self.start.min(other.start);
        let hi = self.end().max(other.end());
        let mut result = MemRegion::new(lo, (hi - lo) as usize, self.region_type);
        result.flags = self.flags | other.flags;
        result.creation_time = self.creation_time.min(other.creation_time);
        Some(result)
    }

    /// Subtracts another region, returning up to two fragments.
    pub fn subtract(&self, other: &MemRegion) -> [Option<MemRegion>; 2] {
        if !self.overlaps(other) {
            return [Some(*self), None];
        }

        let mut fragments = [None, None];

        // Left fragment
        let left_lo = self.start;
        let left_hi = other.start.min(self.end());
        if left_hi > left_lo {
            let mut left = MemRegion::new(left_lo, (left_hi - left_lo) as usize, self.region_type);
            left.flags = self.flags;
            left.creation_time = self.creation_time;
            fragments[0] = Some(left);
        }

        // Right fragment
        let right_lo = other.end().max(self.start);
        let right_hi = self.end();
        if right_hi > right_lo {
            let mut right =
                MemRegion::new(right_lo, (right_hi - right_lo) as usize, self.region_type);
            right.flags = self.flags;
            right.creation_time = self.creation_time;
            fragments[1] = Some(right);
        }

        fragments
    }

    /// Returns a page-aligned version of this region.
    pub fn page_align(self, align: u64) -> MemRegion {
        let start = align_down(self.start, align);
        let end = align_up(self.end(), align);
        let mut result = MemRegion::new(start, (end - start) as usize, self.region_type);
        result.flags = self.flags;
        result.creation_time = self.creation_time;
        result
    }

    /// Returns true if this region is valid.
    pub const fn is_valid(&self) -> bool {
        self.size > 0 && self.start < self.end()
    }

    /// Returns true if this region is available for allocation.
    pub const fn is_available(&self) -> bool {
        matches!(self.region_type, RegionType::Available)
    }
}

impl Default for MemRegion {
    fn default() -> Self {
        Self::new(0, 0, RegionType::Available)
    }
}

// ============================================================================
// REGION STATS
// ============================================================================

/// Snapshot of region statistics.
#[derive(Debug, Clone, Default)]
pub struct RegionStats {
    /// Total number of regions
    pub total_regions: usize,
    /// Number of free regions
    pub free_regions: usize,
    /// Total allocated bytes
    pub allocated_bytes: u64,
    /// Total free bytes
    pub free_bytes: u64,
    /// Number of allocations
    pub allocation_count: u64,
    /// Number of deallocations
    pub deallocation_count: u64,
    /// Number of merge operations
    pub merge_count: u64,
    /// Number of split operations
    pub split_count: u64,
    /// Number of fragments
    pub fragment_count: usize,
    /// Largest free block size
    pub largest_free_block: u64,
}

impl RegionStats {
    /// Creates empty stats.
    pub const fn new() -> Self {
        Self {
            total_regions: 0,
            free_regions: 0,
            allocated_bytes: 0,
            free_bytes: 0,
            allocation_count: 0,
            deallocation_count: 0,
            merge_count: 0,
            split_count: 0,
            fragment_count: 0,
            largest_free_block: 0,
        }
    }

    /// Returns total memory (allocated + free).
    pub const fn total_memory(&self) -> u64 {
        self.allocated_bytes + self.free_bytes
    }

    /// Returns fragmentation ratio (0.0 = no fragmentation, 1.0 = fully fragmented).
    pub fn fragmentation_ratio(&self) -> f64 {
        if self.free_bytes == 0 {
            return 0.0;
        }
        1.0 - (self.largest_free_block as f64 / self.free_bytes as f64)
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Gets current timestamp (TSC).
#[inline]
pub fn get_timestamp() -> u64 {
    // SAFETY: rdtsc is always safe to call
    unsafe { core::arch::x86_64::_rdtsc() }
}
