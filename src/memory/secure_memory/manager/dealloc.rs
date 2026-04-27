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

use x86_64::VirtAddr;

use super::super::error::{SecureMemoryError, SecureMemoryResult};
use super::helpers::{free_virtual_memory, secure_zero_memory};
use super::state::MemoryManager;
use super::stats_internal::MEMORY_STATS;

impl MemoryManager {
    pub(super) fn deallocate_region(&mut self, va: VirtAddr) -> SecureMemoryResult<()> {
        let region_id =
            self.va_to_region.remove(&va.as_u64()).ok_or(SecureMemoryError::AddressNotFound)?;
        let region = self.regions.remove(&region_id).ok_or(SecureMemoryError::RegionNotFound)?;
        secure_zero_memory(va, region.size, region.security_level)?;
        free_virtual_memory(va, region.size)?;
        MEMORY_STATS.record_deallocation(region.size as u64);
        Ok(())
    }
}
