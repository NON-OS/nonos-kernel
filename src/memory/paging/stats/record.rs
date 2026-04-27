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

use super::state::PagingStatistics;
use crate::memory::paging::types::{PagePermissions, PageSize};
use core::sync::atomic::Ordering;

impl PagingStatistics {
    pub fn record_mapping(&self, permissions: PagePermissions, size: PageSize) {
        self.total_mappings.fetch_add(1, Ordering::Relaxed);
        if permissions.contains(PagePermissions::USER) {
            self.user_pages.fetch_add(1, Ordering::Relaxed);
        } else {
            self.kernel_pages.fetch_add(1, Ordering::Relaxed);
        }
        if matches!(size, PageSize::Size2MiB | PageSize::Size1GiB) {
            self.huge_pages.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_unmapping(&self, permissions: PagePermissions, size: PageSize) {
        self.total_mappings.fetch_sub(1, Ordering::Relaxed);
        if permissions.contains(PagePermissions::USER) {
            self.user_pages.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.kernel_pages.fetch_sub(1, Ordering::Relaxed);
        }
        if matches!(size, PageSize::Size2MiB | PageSize::Size1GiB) {
            self.huge_pages.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn record_page_fault(&self) {
        self.page_faults.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn record_tlb_flush(&self) {
        self.tlb_flushes.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn record_cow_fault(&self) {
        self.cow_faults.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn record_demand_load(&self) {
        self.demand_loads.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn record_modification(&self) {
        self.page_modifications.fetch_add(1, Ordering::Relaxed);
    }
}
