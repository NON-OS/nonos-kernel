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

use super::super::constants::{align_down, align_up};
use super::mem_region::MemRegion;

impl MemRegion {
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
}
