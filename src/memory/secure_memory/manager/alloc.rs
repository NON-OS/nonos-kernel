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

use crate::memory::addr::VirtAddr;

use super::super::constants::*;
use super::super::error::{SecureMemoryError, SecureMemoryResult};
use super::super::types::*;
use super::helpers::{allocate_virtual_memory, get_physical_address, get_timestamp, zero_on_alloc};
use super::state::MemoryManager;
use super::stats_internal::MEMORY_STATS;

impl MemoryManager {
    pub(super) fn allocate_region(
        &mut self,
        size: usize,
        region_type: RegionType,
        security_level: SecurityLevel,
        owner_process: u64,
    ) -> SecureMemoryResult<VirtAddr> {
        if !self.initialized {
            return Err(SecureMemoryError::NotInitialized);
        }
        if size < MIN_ALLOCATION_SIZE || size > MAX_ALLOCATION_SIZE {
            return Err(SecureMemoryError::InvalidSize);
        }
        if self.regions.len() >= MAX_REGIONS {
            return Err(SecureMemoryError::RegionLimitExceeded);
        }

        let va = allocate_virtual_memory(size)?;
        zero_on_alloc(va, size);
        let pa = get_physical_address(va)?;

        let region_id = self.next_region_id;
        self.next_region_id = self.next_region_id.wrapping_add(1);
        if self.next_region_id == INVALID_REGION_ID {
            self.next_region_id = INITIAL_REGION_ID;
        }

        let region = MemoryRegion::new(
            region_id,
            va,
            pa,
            size,
            region_type,
            security_level,
            owner_process,
            get_timestamp(),
        );
        self.regions.insert(region_id, region);
        self.va_to_region.insert(va.as_u64(), region_id);
        MEMORY_STATS.record_allocation(size as u64);
        Ok(va)
    }
}
