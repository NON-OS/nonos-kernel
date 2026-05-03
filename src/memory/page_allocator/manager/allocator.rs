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

use super::super::constants::INITIAL_PAGE_ID;
use super::super::error::PageAllocResult;
use super::super::types::AllocatedPage;
use crate::memory::addr::VirtAddr;
use alloc::vec::Vec;

pub(super) struct PageAllocator {
    pub(super) allocated_pages: Vec<AllocatedPage>,
    pub(super) next_page_id: u64,
    pub(super) initialized: bool,
}

impl PageAllocator {
    pub(super) const fn new() -> Self {
        Self { allocated_pages: Vec::new(), next_page_id: INITIAL_PAGE_ID, initialized: false }
    }

    pub(super) fn init(&mut self) -> PageAllocResult<()> {
        if self.initialized {
            return Ok(());
        }
        self.allocated_pages.clear();
        self.next_page_id = INITIAL_PAGE_ID;
        self.initialized = true;
        Ok(())
    }

    pub(super) fn get_page_info(&self, va: VirtAddr) -> Option<&AllocatedPage> {
        self.allocated_pages.iter().find(|p| p.virtual_addr == va)
    }
}
