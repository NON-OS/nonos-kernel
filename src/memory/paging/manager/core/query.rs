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

use super::types::PagingManager;
use x86_64::PhysAddr;

impl PagingManager {
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn active_page_table(&self) -> Option<PhysAddr> {
        self.active_page_table
    }

    pub fn mappings_count(&self) -> usize {
        self.mappings.len()
    }

    pub fn address_spaces_count(&self) -> usize {
        self.address_spaces.len()
    }

    pub fn lookup_asid_for_process(&self, process_id: u32) -> Option<u32> {
        for (asid, addr_space) in &self.address_spaces {
            if addr_space.process_id == process_id {
                return Some(*asid);
            }
        }
        None
    }
}
