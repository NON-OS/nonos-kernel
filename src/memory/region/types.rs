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

use x86_64::VirtAddr;
use super::constants::*;
// ============================================================================
// REGION TYPE
// ============================================================================
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegionType {
    Available,
    Reserved,
    Kernel,
    User,
    Stack,
    Heap,
    Mmio,
    Firmware,
    Bootloader,
    Dma,
    Guard,
    Shared,
}

impl RegionType {
    pub const fn is_allocatable(&self) -> bool {
        matches!(self, Self::Available)
    }

    pub const fn is_kernel(&self) -> bool {
        matches!(self, Self::Kernel | Self::Stack | Self::Heap)
    }

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionFlags {
    Readable,
    Writable,
    Executable,
    Cacheable,
    Shared,
    Locked,
    Protected,
    Encrypted,
}

impl RegionFlags {
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
#[derive(Debug, Clone, Copy)]
pub struct MemRegion {
    pub start: u64,
    pub size: usize,
    pub region_type: RegionType,
    pub flags: u32,
    pub creation_time: u64,
    pub access_count: u64,
}

impl MemRegion {
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

    pub fn start_addr(&self) -> VirtAddr {
        VirtAddr::new(self.start)
    }

    pub const fn end(&self) -> u64 {
        self.start + self.size as u64
    }

    pub fn end_addr(&self) -> VirtAddr {
        VirtAddr::new(self.end())
    }

    pub const fn size_bytes(&self) -> u64 {
        self.size as u64
    }

    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }

    pub const fn contains_range(&self, other: &MemRegion) -> bool {
        other.start >= self.start && other.end() <= self.end()
    }

    pub const fn overlaps(&self, other: &MemRegion) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    pub fn has_flag(&self, flag: RegionFlags) -> bool {
        (self.flags & flag.bit()) != 0
    }

    pub fn set_flag(&mut self, flag: RegionFlags) {
        self.flags |= flag.bit();
    }

    pub fn clear_flag(&mut self, flag: RegionFlags) {
        self.flags &= !flag.bit();
    }

    pub fn union(&self, other: &MemRegion) -> Option<MemRegion> {
        if self.region_type != other.region_type {
            return None;
        }

        if self.end() < other.start && other.end() < self.start {
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

    pub fn subtract(&self, other: &MemRegion) -> [Option<MemRegion>; 2] {
        if !self.overlaps(other) {
            return [Some(*self), None];
        }

        let mut fragments = [None, None];
        let left_lo = self.start;
        let left_hi = other.start.min(self.end());
        if left_hi > left_lo {
            let mut left = MemRegion::new(left_lo, (left_hi - left_lo) as usize, self.region_type);
            left.flags = self.flags;
            left.creation_time = self.creation_time;
            fragments[0] = Some(left);
        }

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

    pub fn page_align(self, align: u64) -> MemRegion {
        let start = align_down(self.start, align);
        let end = align_up(self.end(), align);
        let mut result = MemRegion::new(start, (end - start) as usize, self.region_type);
        result.flags = self.flags;
        result.creation_time = self.creation_time;
        result
    }

    pub const fn is_valid(&self) -> bool {
        self.size > 0 && self.start < self.end()
    }

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
#[derive(Debug, Clone, Default)]
pub struct RegionStats {
    pub total_regions: usize,
    pub free_regions: usize,
    pub allocated_bytes: u64,
    pub free_bytes: u64,
    pub allocation_count: u64,
    pub deallocation_count: u64,
    pub merge_count: u64,
    pub split_count: u64,
    pub fragment_count: usize,
    pub largest_free_block: u64,
}

impl RegionStats {
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

    pub const fn total_memory(&self) -> u64 {
        self.allocated_bytes + self.free_bytes
    }
    /// (0.0 = no fragmentation, 1.0 = fully fragmented).
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
#[inline]
pub fn get_timestamp() -> u64 {
    // SAFETY: rdtsc is always safe to call
    unsafe { core::arch::x86_64::_rdtsc() }
}
