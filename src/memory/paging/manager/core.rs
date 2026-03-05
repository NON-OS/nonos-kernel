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

extern crate alloc;

use alloc::collections::BTreeMap;
use x86_64::registers::control::Cr3;
use x86_64::PhysAddr;

use crate::memory::paging::constants::FIRST_USER_ASID;
use crate::memory::paging::error::PagingResult;
use crate::memory::paging::types::{AddressSpace, PageMapping};

pub struct PagingManager {
    pub(crate) active_page_table: Option<PhysAddr>,
    pub(crate) mappings: BTreeMap<u64, PageMapping>,
    pub(crate) address_spaces: BTreeMap<u32, AddressSpace>,
    pub(crate) next_asid: u32,
    pub(crate) initialized: bool,
}

impl PagingManager {
    pub const fn new() -> Self {
        Self {
            active_page_table: None,
            mappings: BTreeMap::new(),
            address_spaces: BTreeMap::new(),
            next_asid: FIRST_USER_ASID,
            initialized: false,
        }
    }

    pub fn init(&mut self) -> PagingResult<()> {
        if self.initialized {
            return Ok(());
        }

        let (cr3_frame, _) = Cr3::read();
        self.active_page_table = Some(cr3_frame.start_address());
        self.initialized = true;

        self.create_kernel_address_space()?;
        Ok(())
    }

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
}

impl Default for PagingManager {
    fn default() -> Self {
        Self::new()
    }
}
