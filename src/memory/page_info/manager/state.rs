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

use super::super::error::PageInfoResult;
use super::super::types::{PageInfo, PageStats};
use alloc::collections::BTreeMap;
use spin::Mutex;

pub(super) struct PageInfoManager {
    pub pages: BTreeMap<u64, PageInfo>,
    pub initialized: bool,
}

impl PageInfoManager {
    pub(super) const fn new() -> Self {
        Self { pages: BTreeMap::new(), initialized: false }
    }

    pub(super) fn init(&mut self) -> PageInfoResult<()> {
        if self.initialized {
            return Ok(());
        }
        self.pages.clear();
        self.initialized = true;
        Ok(())
    }
}

pub(super) static PAGE_INFO_MANAGER: Mutex<PageInfoManager> = Mutex::new(PageInfoManager::new());
pub(super) static PAGE_STATS: PageStats = PageStats::new();
