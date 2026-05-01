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

use crate::memory::addr::{PhysAddr, VirtAddr};

use super::super::core::PagingManager;
use crate::memory::paging::constants::page_align_down;
use crate::memory::paging::error::{PagingError, PagingResult};
use crate::memory::paging::stats::PagingStatistics;
use crate::memory::paging::types::{PageMapping, PagePermissions, PageSize};

impl PagingManager {
    pub fn map_page(
        &mut self,
        virtual_addr: VirtAddr,
        physical_addr: PhysAddr,
        permissions: PagePermissions,
        size: PageSize,
        stats: &PagingStatistics,
    ) -> PagingResult<()> {
        if !self.initialized {
            return Err(PagingError::NotInitialized);
        }

        if permissions.is_wx_violation() {
            return Err(PagingError::WXViolation);
        }

        let pte_flags = permissions.to_pte_flags();
        self.install_mapping(virtual_addr, physical_addr, pte_flags)?;

        let mapping = PageMapping::new(virtual_addr, physical_addr, size, permissions);
        let page_addr = page_align_down(virtual_addr.as_u64());
        self.mappings.insert(page_addr, mapping);

        stats.record_mapping(permissions, size);

        Ok(())
    }
}
