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

use super::super::constants::KERNEL_PROCESS_ID;
use super::super::types::{RegionType, SecurityLevel};
use super::state::MemoryManager;

impl MemoryManager {
    pub(super) fn validate_access(&self, process_id: u64, va: VirtAddr, write: bool) -> bool {
        if let Some(region) = self.get_region_info(va) {
            if region.owner_process != process_id && region.owner_process != KERNEL_PROCESS_ID {
                return false;
            }
            match region.region_type {
                RegionType::Code => !write,
                RegionType::Data | RegionType::Stack | RegionType::Heap | RegionType::Device => {
                    true
                }
                RegionType::Capsule => region.security_level >= SecurityLevel::Confidential,
            }
        } else {
            false
        }
    }
}
