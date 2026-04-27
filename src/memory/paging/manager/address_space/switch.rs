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

use super::super::core::PagingManager;
use crate::memory::paging::error::{PagingError, PagingResult};

impl PagingManager {
    pub fn switch_address_space(&mut self, asid: u32) -> PagingResult<()> {
        let address_space =
            self.address_spaces.get(&asid).ok_or(PagingError::AddressSpaceNotFound)?;
        unsafe {
            core::arch::asm!(
                "mov cr3, {}",
                in(reg) address_space.cr3_value.as_u64(),
                options(nostack, preserves_flags)
            );
        }
        self.active_page_table = Some(address_space.cr3_value);
        Ok(())
    }
}
