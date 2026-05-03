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

use super::super::constants::MAX_TRACKED_PAGES;
use super::super::error::{PageInfoError, PageInfoResult};
use super::super::types::{PageFlags, PageInfo};
use super::state::{PageInfoManager, PAGE_STATS};
use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::layout;

impl PageInfoManager {
    pub(super) fn add_page(
        &mut self,
        pa: PhysAddr,
        va: Option<VirtAddr>,
        flags: PageFlags,
    ) -> PageInfoResult<()> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        if self.pages.len() >= MAX_TRACKED_PAGES {
            return Err(PageInfoError::TooManyPages);
        }
        let info = PageInfo::new(pa, va, flags);
        self.pages.insert(page_num, info);
        PAGE_STATS.increment_total();
        if va.is_some() {
            PAGE_STATS.increment_mapped();
        }
        if flags.contains(PageFlags::DIRTY) {
            PAGE_STATS.increment_dirty();
        }
        if flags.contains(PageFlags::LOCKED) {
            PAGE_STATS.increment_locked();
        }
        Ok(())
    }

    pub(super) fn remove_page(&mut self, pa: PhysAddr) -> PageInfoResult<()> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        if let Some(info) = self.pages.remove(&page_num) {
            PAGE_STATS.decrement_total();
            if info.virtual_addr.is_some() {
                PAGE_STATS.decrement_mapped();
            }
            if info.flags.contains(PageFlags::DIRTY) {
                PAGE_STATS.decrement_dirty();
            }
            if info.flags.contains(PageFlags::LOCKED) {
                PAGE_STATS.decrement_locked();
            }
            Ok(())
        } else {
            Err(PageInfoError::PageNotFound)
        }
    }

    pub(super) fn get_page_info(&self, pa: PhysAddr) -> Option<PageInfo> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        self.pages.get(&page_num).copied()
    }
}
