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

use crate::memory::addr::PhysAddr;
use crate::memory::paging::constants::FIRST_USER_ASID;
use crate::memory::paging::types::{AddressSpace, PageMapping};
use alloc::collections::BTreeMap;

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
}

impl Default for PagingManager {
    fn default() -> Self {
        Self::new()
    }
}
