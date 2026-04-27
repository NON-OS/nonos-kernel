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

use super::super::constants::PAGE_SIZE_U64;
use super::super::error::{BootMemoryError, BootMemoryResult};
use super::state::BootMemoryManager;

impl BootMemoryManager {
    pub(super) fn find_next_free(&mut self) -> BootMemoryResult<()> {
        for region in &self.regions {
            if region.is_available() && region.size() >= PAGE_SIZE_U64 {
                self.next_free = region.start;
                return Ok(());
            }
        }
        Err(BootMemoryError::NoAvailableMemory)
    }

    pub(super) fn calculate_totals(&mut self) {
        self.total_size = self.regions.iter().map(|r| r.size()).sum();
    }

    pub(super) fn validate_layout(&self) -> BootMemoryResult<()> {
        if self.regions.is_empty() {
            return Err(BootMemoryError::NoRegionsDefined);
        }
        let mut has_available = false;
        for region in &self.regions {
            if region.start >= region.end {
                return Err(BootMemoryError::InvalidRegionBounds);
            }
            if region.is_available() {
                has_available = true;
            }
        }
        if !has_available {
            return Err(BootMemoryError::NoAvailableMemory);
        }
        Ok(())
    }
}
