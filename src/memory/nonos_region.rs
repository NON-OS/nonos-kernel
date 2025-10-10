//! Memory Region Management

use x86_64::VirtAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemRegion {
    pub start: u64,   // inclusive
    pub size: usize,  // bytes
}

impl MemRegion {
    pub const fn new(start: u64, size: usize) -> Self {
        Self { start, size }
    }

    #[inline]
    pub fn start_addr(&self) -> VirtAddr { VirtAddr::new(self.start) }

    #[inline]
    pub fn end(&self) -> u64 { self.start.saturating_add(self.size as u64) }

    #[inline]
    pub fn end_addr(&self) -> VirtAddr { VirtAddr::new(self.end()) }

    #[inline]
    pub fn size_bytes(&self) -> u64 { self.size as u64 }

    #[inline]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }

    #[inline]
    pub fn contains_range(&self, other: MemRegion) -> bool {
        other.start >= self.start && other.end() <= self.end()
    }

    #[inline]
    pub fn overlaps(&self, other: MemRegion) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    // Return a union if overlapping or touching; otherwise None.
    pub fn union(&self, other: MemRegion) -> Option<MemRegion> {
        if self.end() < other.start || other.end() < self.start {
            // Disjoint with a gap
            if self.end() == other.start || other.end() == self.start {
                let lo = self.start.min(other.start);
                let hi = self.end().max(other.end());
                return Some(MemRegion::new(lo, (hi - lo) as usize));
            }
            return None;
        }
        let lo = self.start.min(other.start);
        let hi = self.end().max(other.end());
        Some(MemRegion::new(lo, (hi - lo) as usize))
    }

    // Subtract other from self; returns up to two remaining fragments.
    pub fn subtract(&self, other: MemRegion) -> [Option<MemRegion>; 2] {
        if !self.overlaps(other) {
            return [Some(*self), None];
        }
        let mut out = [None, None];
        let left_lo = self.start;
        let left_hi = other.start.min(self.end());
        if left_hi > left_lo {
            out[0] = Some(MemRegion::new(left_lo, (left_hi - left_lo) as usize));
        }
        let right_lo = other.end().max(self.start);
        let right_hi = self.end();
        if right_hi > right_lo {
            out[1] = Some(MemRegion::new(right_lo, (right_hi - right_lo) as usize));
        }
        out
    }

    // Align the region to [align]-byte pages (down start, up end).
    pub fn page_align(self, align: u64) -> MemRegion {
        let start = self.start & !(align - 1);
        let end = (self.end() + align - 1) & !(align - 1);
        MemRegion::new(start, (end - start) as usize)
    }
}
