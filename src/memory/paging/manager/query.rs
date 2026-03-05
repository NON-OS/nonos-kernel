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

use super::core::PagingManager;
use crate::memory::paging::constants::page_align_down;
use crate::memory::paging::types::PageMapping;

impl PagingManager {
    pub fn get_mapping_info(&self, virtual_addr: VirtAddr) -> Option<&PageMapping> {
        let page_addr = page_align_down(virtual_addr.as_u64());
        self.mappings.get(&page_addr)
    }

    pub fn get_mapping_info_mut(&mut self, virtual_addr: VirtAddr) -> Option<&mut PageMapping> {
        let page_addr = page_align_down(virtual_addr.as_u64());
        self.mappings.get_mut(&page_addr)
    }
}
