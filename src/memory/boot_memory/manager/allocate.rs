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

use super::super::constants::*;
use super::super::error::{BootMemoryError, BootMemoryResult};
use super::helpers::align_up;
use super::state::{BootMemoryManager, ALLOCATION_COUNT, AVAILABLE_MEMORY};
use crate::memory::addr::PhysAddr;
use core::sync::atomic::Ordering;

impl BootMemoryManager {
    pub(super) fn allocate_aligned(
        &mut self,
        size: usize,
        alignment: usize,
    ) -> BootMemoryResult<PhysAddr> {
        if size == 0 {
            return Err(BootMemoryError::InvalidAlignment);
        }
        if size > MAX_ALLOCATION_SIZE {
            return Err(BootMemoryError::AllocationTooLarge);
        }

        let align = if alignment == 0 { PAGE_SIZE } else { alignment };
        if align & (align - 1) != 0 {
            return Err(BootMemoryError::InvalidAlignment);
        }

        let needed = align_up(size as u64, align as u64);
        let next_free_val = self.next_free.as_u64();

        for region in &self.regions {
            if !region.is_available() {
                continue;
            }
            let start = if next_free_val > region.start.as_u64() {
                align_up(next_free_val, align as u64)
            } else {
                align_up(region.start.as_u64(), align as u64)
            };
            let end = start.saturating_add(needed);

            if start >= region.start.as_u64() && end <= region.end.as_u64() {
                self.next_free = PhysAddr::new(end);
                self.allocated_size = self.allocated_size.saturating_add(needed);
                ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
                AVAILABLE_MEMORY.fetch_sub(needed, Ordering::Relaxed);
                return Ok(PhysAddr::new(start));
            }
        }
        Err(BootMemoryError::OutOfMemory)
    }
}
