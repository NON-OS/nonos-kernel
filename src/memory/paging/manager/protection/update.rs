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

use super::super::core::PagingManager;
use crate::memory::paging::constants::page_align_down;
use crate::memory::paging::error::{PagingError, PagingResult};
use crate::memory::paging::stats::PagingStatistics;
use crate::memory::paging::types::{get_timestamp, PagePermissions};

impl PagingManager {
    pub fn update_page_flags(
        &mut self,
        virtual_addr: VirtAddr,
        new_permissions: PagePermissions,
        stats: &PagingStatistics,
    ) -> PagingResult<()> {
        if new_permissions.is_wx_violation() {
            return Err(PagingError::WXViolation);
        }

        let page_addr = page_align_down(virtual_addr.as_u64());

        let mapping = self.mappings.get_mut(&page_addr).ok_or(PagingError::PageNotMapped)?;

        mapping.permissions = new_permissions;
        mapping.last_accessed = get_timestamp();

        let pte_flags = new_permissions.to_pte_flags();
        self.update_pte(virtual_addr, pte_flags)?;

        stats.record_modification();

        Ok(())
    }
}
