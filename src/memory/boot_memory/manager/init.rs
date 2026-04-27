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
use super::super::error::BootMemoryResult;
use super::super::types::{BootHandoff, RegionType};
use super::state::BootMemoryManager;

impl BootMemoryManager {
    pub(super) fn init_from_handoff(&mut self, handoff_addr: u64) -> BootMemoryResult<()> {
        if handoff_addr == 0 {
            return self.init_default();
        }

        let handoff = unsafe {
            let ptr = handoff_addr as *const BootHandoff;
            if ptr.is_null() {
                return self.init_default();
            }
            ptr.read_volatile()
        };

        if let Err(e) = handoff.validate() {
            if e.can_use_defaults() {
                return self.init_default();
            }
            return Err(e);
        }

        self.setup_regions_from_handoff(&handoff)?;
        self.validate_layout()?;
        self.initialized = true;
        Ok(())
    }

    pub(super) fn init_default(&mut self) -> BootMemoryResult<()> {
        self.regions.clear();
        self.add_region(
            CONVENTIONAL_MEMORY_START,
            CONVENTIONAL_MEMORY_END,
            RegionType::Reserved,
            0,
        );
        self.add_region(DEFAULT_KERNEL_START, DEFAULT_KERNEL_END, RegionType::Kernel, 0);
        self.add_region(DEFAULT_AVAILABLE_START, DEFAULT_AVAILABLE_END, RegionType::Available, 0);
        self.add_hardware_regions();
        self.find_next_free()?;
        self.calculate_totals();
        self.initialized = true;
        Ok(())
    }
}
